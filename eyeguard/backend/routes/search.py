"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..api_clients.abuse import AbuseIPDBClient
from ..api_clients.base import ThreatClientError
from ..api_clients.otx import OTXClient
from ..api_clients.transformers import transform_abuse, transform_otx, transform_vt
from ..api_clients.vt import VirusTotalClient
from ..cache import cache_provider
from ..config import get_settings
from ..database import get_db
from ..logging_config import logger
from ..models.schemas import ComputedVerdict, Device, IndicatorSearchResponse, IpReputation, IpSearchResponse, SourceIntel
from ..utils.ip_tools import normalize_ip
from ..utils.rate_limiter import rate_limiter
from ..utils.rules import compute_verdict
from ..utils.state import state_store
from ..services import ti_aggregator

router = APIRouter(prefix="/api/v1", tags=["search"])
ip_router = APIRouter(prefix="/api", tags=["search"])
settings = get_settings()
CACHE_WINDOW_SECONDS = 300
_ip_lookup_cache: Dict[tuple[str, int], tuple[float, Dict[str, Any]]] = {}


async def _safe_fetch(client, ip: str) -> dict[str, Any]:
    try:
        return await client.fetch(ip)
    except ThreatClientError:
        logger.warning("intel.fetch_fallback", provider=client.name, ip=ip)
        return client.load_mock(ip)
    except Exception:
        logger.warning("intel.fetch_error", provider=client.name, ip=ip)
        return client.load_mock(ip)


async def _persist_reputation(
    db: AsyncSession,
    ip_model: IpReputation,
    vt_payload: dict[str, Any],
    otx_payload: dict[str, Any],
    abuse_payload: dict[str, Any],
    rationale: str,
) -> None:
    try:
        data = ip_model.model_dump()
        result = await db.execute(
            text(
                """
                INSERT INTO ip_reputation (ip_address, severity, recommended_action, verdict, rationale, recent_alerts, related_devices)
                VALUES (:ip_address, :severity, :recommended_action, :verdict, :rationale, :recent_alerts, :related_devices)
                RETURNING id
                """
            ),
            {
                "ip_address": data["ip"],
                "severity": data["computed_verdict"]["severity"],
                "recommended_action": data["computed_verdict"]["action"],
                "verdict": data["computed_verdict"]["severity"],
                "rationale": rationale,
                "recent_alerts": json.dumps(data["recent_alerts"], default=str),
                "related_devices": json.dumps(data["related_devices"], default=str),
            },
        )
        reputation_id = result.scalar_one()
        await db.execute(
            text(
                """
                INSERT INTO virustotal_responses (reputation_id, raw_response, malicious_count, suspicious_count)
                VALUES (:reputation_id, :raw_response, :malicious, :suspicious)
                """
            ),
            {
                "reputation_id": reputation_id,
                "raw_response": json.dumps(vt_payload, default=str),
                "malicious": vt_payload.get("malicious_count", 0),
                "suspicious": vt_payload.get("suspicious_count", 0),
            },
        )
        await db.execute(
            text(
                """
                INSERT INTO otx_responses (reputation_id, raw_response, pulse_count, reference_count)
                VALUES (:reputation_id, :raw_response, :pulse_count, :reference_count)
                """
            ),
            {
                "reputation_id": reputation_id,
                "raw_response": json.dumps(otx_payload, default=str),
                "pulse_count": otx_payload.get("pulse_count", 0),
                "reference_count": otx_payload.get("reference_count", 0),
            },
        )
        await db.execute(
            text(
                """
                INSERT INTO abuseipdb_responses (reputation_id, raw_response, abuse_score, total_reports)
                VALUES (:reputation_id, :raw_response, :abuse_score, :total_reports)
                """
            ),
            {
                "reputation_id": reputation_id,
                "raw_response": json.dumps(abuse_payload, default=str),
                "abuse_score": abuse_payload.get("abuse_score", 0),
                "total_reports": abuse_payload.get("total_reports", 0),
            },
        )
        await db.commit()
    except Exception as exc:
        logger.warning("intel.persist_failed", error=str(exc))
        await db.rollback()


async def _fetch_related_devices(db: AsyncSession, ip: str) -> list[Device]:
    try:
        result = await db.execute(
            text(
                """
                SELECT id::text, ip_address::text, hostname, device_type, owner_role, traffic_gb, status, last_seen_at
                FROM devices
                WHERE ip_address = :ip OR ip_address << :network
                ORDER BY last_seen_at DESC NULLS LAST
                LIMIT 5
                """
            ),
            {"ip": ip, "network": f"{ip}/32"},
        )
        rows = result.mappings().all()
        return [Device(**dict(row)) for row in rows]
    except Exception:
        return []


async def _fetch_recent_alerts(db: AsyncSession, ip: str) -> list[dict[str, Any]]:
    try:
        result = await db.execute(
            text(
                """
                SELECT id::text, detected_at, severity, status, category
                FROM alerts
                WHERE source_ip = :ip
                ORDER BY detected_at DESC
                LIMIT 5
                """
            ),
            {"ip": ip},
        )
        rows = result.mappings().all()
        return [dict(row) for row in rows]
    except Exception:
        return []


@router.get("/search", response_model=IpReputation)
async def search_ip(ip: str, response: Response, db: AsyncSession = Depends(get_db)) -> IpReputation:
    try:
        normalized = normalize_ip(ip)
    except ValueError as exc:
        logger.warning("intel.invalid_ip", ip=ip)
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_IP", "message": str(exc)}) from exc

    rate_key = f"search:{normalized}"
    if not await rate_limiter.check(rate_key):
        logger.warning("intel.rate_limited", ip=normalized)
        raise HTTPException(status_code=429, detail={"error_code": "RATE_LIMIT", "message": "Too many requests"})

    cache_key = f"ip-reputation:{normalized}"
    cached = await cache_provider.get(cache_key)
    if cached:
        payload = cached.value if hasattr(cached, "value") else cached
        data = json.loads(payload) if isinstance(payload, str) else payload
        response.headers["X-Cache-Hit"] = "1"
        logger.info("intel.cache_hit", ip=normalized)
        return IpReputation(**data)

    response.headers["X-Cache-Hit"] = "0"
    logger.info("intel.lookup_start", ip=normalized)
    vt_raw, otx_raw, abuse_raw = await asyncio.gather(
        _safe_fetch(VirusTotalClient(settings.vt_api_key), normalized),
        _safe_fetch(OTXClient(settings.otx_api_key), normalized),
        _safe_fetch(AbuseIPDBClient(settings.abuse_api_key), normalized),
    )

    vt_normalized = transform_vt(vt_raw)
    otx_normalized = transform_otx(otx_raw)
    abuse_normalized = transform_abuse(abuse_raw)

    severity, action, rationale = compute_verdict(vt_normalized, otx_normalized, abuse_normalized)

    recent_alerts: list[dict[str, Any]] = []
    related_devices: list[Device] = []
    if db:
        recent_alerts = await _fetch_recent_alerts(db, normalized)
        related_devices = await _fetch_related_devices(db, normalized)

    aggregated = {
        "ip": normalized,
        "vt_summary": vt_normalized["summary"],
        "abuse_summary": abuse_normalized["summary"],
        "otx_summary": otx_normalized["summary"],
        "computed_verdict": {"severity": severity, "action": action},
        "rationale": rationale,
        "recent_alerts": recent_alerts,
        "related_devices": [device.model_dump() for device in related_devices],
    }

    ip_model = IpReputation(**aggregated)
    await cache_provider.set(cache_key, json.dumps(ip_model.model_dump(), default=str), ex=3600)

    if db:
        await _persist_reputation(db, ip_model, vt_normalized, otx_normalized, abuse_normalized, rationale)

    logger.info("intel.lookup_complete", ip=normalized, severity=severity, action=action)
    return ip_model


def _build_source(provider: str, payload: dict[str, Any]) -> SourceIntel:
    return SourceIntel(provider=provider, data=payload)


def _summarize_sources(vt: dict[str, Any], otx: dict[str, Any], abuse: dict[str, Any]) -> str:
    vt_line = f"VT malicious={vt.get('malicious_count', 0)} suspicious={vt.get('suspicious_count', 0)}"
    otx_line = f"OTX pulses={otx.get('pulse_count', 0)} references={otx.get('reference_count', 0)}"
    abuse_line = f"AbuseIPDB score={abuse.get('abuse_score', 0)} reports={abuse.get('total_reports', 0)}"
    return "; ".join([vt_line, otx_line, abuse_line])


@ip_router.get("/search/ip", response_model=IpSearchResponse)
async def simple_ip_lookup(ip: str) -> IpSearchResponse:
    try:
        normalized = normalize_ip(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc

    now = time.time()
    revision = state_store.integration_keys_revision()
    cache_key = (normalized, revision)
    cached = _ip_lookup_cache.get(cache_key)
    if cached and now - cached[0] < CACHE_WINDOW_SECONDS:
        logger.info("ip.lookup.cache_hit", ip=normalized)
        return IpSearchResponse(**cached[1])

    overrides = state_store.get_integration_keys()
    vt_key = overrides.get("vt_api_key") or settings.vt_api_key
    otx_key = overrides.get("otx_api_key") or settings.otx_api_key
    abuse_key = overrides.get("abuse_api_key") or settings.abuse_api_key
    missing: list[str] = []
    if not vt_key:
        missing.append("virustotal")
    if not otx_key:
        missing.append("otx")
    if not abuse_key:
        missing.append("abuseipdb")

    vt_raw, otx_raw, abuse_raw = await asyncio.gather(
        _safe_fetch(VirusTotalClient(vt_key), normalized),
        _safe_fetch(OTXClient(otx_key), normalized),
        _safe_fetch(AbuseIPDBClient(abuse_key), normalized),
    )
    vt_norm = transform_vt(vt_raw)
    otx_norm = transform_otx(otx_raw)
    abuse_norm = transform_abuse(abuse_raw)
    severity, action, rationale = compute_verdict(vt_norm, otx_norm, abuse_norm)

    malicious_sources: list[str] = []
    if vt_norm.get("malicious_count", 0):
        malicious_sources.append("virustotal")
    if otx_norm.get("pulse_count", 0):
        malicious_sources.append("otx")
    if abuse_norm.get("abuse_score", 0) >= 50:
        malicious_sources.append("abuseipdb")
    if severity == "High" and "high-confidence" not in malicious_sources:
        malicious_sources.append("high-confidence")

    summary_text = _summarize_sources(vt_norm, otx_norm, abuse_norm)
    alert_summaries: list[dict[str, Any]] = []
    device_summaries: list[dict[str, Any]] = []
    activity_timeline: list[dict[str, Any]] = []
    blocked = False

    async with state_store._lock:  # type: ignore[attr-defined]
        blocked = state_store.is_ip_blocked(normalized)
        matched_alerts = state_store.find_alerts_by_ip(normalized)
        alert_summaries = [
            {
                "id": item.id,
                "category": item.category,
                "severity": item.severity,
                "status": item.status,
                "detected_at": item.detected_at,
                "playbook": item.playbook,
                "recommended_actions": item.recommended_actions,
                "mitigation_steps": item.mitigation_steps,
            }
            for item in matched_alerts
        ][:8]
        device_summaries = [
            device.model_dump()
            for device in state_store.find_devices_by_ip(normalized)[:5]
        ]
        activity_timeline = [
            {
                "id": entry["id"],
                "event": entry["event"],
                "actor": entry["actor"],
                "created_at": entry["created_at"],
                "metadata": entry["metadata"],
            }
            for entry in state_store.recent_activity_for_indicator(normalized)
        ][:10]
        if severity == "High":
            state_store.record_threat_alert(
                {
                    "id": str(uuid.uuid4()),
                    "user_id": "global-alerts",
                    "indicator": normalized,
                    "created_at": datetime.utcnow(),
                    "severity": severity,
                    "sources": malicious_sources,
                    "recommended_action": action,
                    "rationale": rationale,
                }
            )

    payload = IpSearchResponse(
        ip=normalized,
        source_results={
            "virustotal": _build_source("virustotal", vt_norm),
            "otx": _build_source("otx", otx_norm),
            "abuseipdb": _build_source("abuseipdb", abuse_norm),
        },
        aggregated_summary=summary_text,
        missing_api_keys=missing,
        computed_verdict=ComputedVerdict(severity=severity, action=action),
        verdict_rationale=rationale,
        blocked=blocked,
        resolved_ips=[normalized],
        recent_alerts=alert_summaries,
        related_devices=device_summaries,
        malicious_sources=malicious_sources,
        intel_summary=rationale,
        activity_log=activity_timeline,
    )
    _ip_lookup_cache[cache_key] = (now, payload.model_dump())
    state_store.log_activity(
        actor="search-service",
        event="ip.lookup",
        metadata={
            "ip": normalized,
            "missing_keys": missing,
            "severity": severity,
        },
    )
    if severity == "High":
        recipients = state_store.collect_global_alert_recipients()
        if recipients:
            lines = [
                f"Severity: {severity}",
                f"Recommended action: {action}",
                f"Indicator: {normalized}",
                f"Sources: {', '.join(malicious_sources) if malicious_sources else 'none'}",
                "",
                "Intel summary:",
                summary_text,
            ]
            if alert_summaries:
                lines.append("")
                lines.append("Related alerts:")
                for entry in alert_summaries[:3]:
                    timestamp = entry["detected_at"]
                    if hasattr(timestamp, "isoformat"):
                        timestamp = timestamp.isoformat()
                    lines.append(f" - {timestamp} {entry['category']} ({entry['severity']})")
            state_store.send_email(
                subject=f"[EyeGuard] Malicious IP detected: {normalized}",
                body="".join(lines),
                recipients=recipients,
                category="ti.lookup",
                metadata={"ip": normalized, "severity": severity, "sources": malicious_sources},
            )
    return payload


@ip_router.get("/search/indicator", response_model=IndicatorSearchResponse)
async def indicator_lookup(value: str, indicator_type: str = "url") -> IndicatorSearchResponse:
    try:
        result = await ti_aggregator.lookup_indicator(indicator_type, value, user_id="indicator-service")
    except ti_aggregator.IndicatorValidationError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("indicator.lookup_failed", indicator=value, indicator_type=indicator_type, error=str(exc))
        raise HTTPException(status_code=500, detail={"error": "Unable to complete indicator lookup."}) from exc

    intel_summary = result.aggregated_summary.get("summary_text")
    mal_sources = result.aggregated_summary.get("malicious_sources", [])
    has_alerts = bool(result.aggregated_summary.get("is_malicious"))

    return IndicatorSearchResponse(
        type=result.indicator_type,
        value=result.value,
        resolved_ips=result.resolved_ips,
        source_results=result.source_results,
        aggregated_summary=result.aggregated_summary,
        missing_api_keys=result.missing_api_keys,
        cached=result.cached,
        has_alerts=has_alerts,
        malicious_sources=mal_sources,
        intel_summary=intel_summary,
    )
