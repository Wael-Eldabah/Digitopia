"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..api_clients.abuse import AbuseIPDBClient
from ..api_clients.base import ThreatClientError
from ..api_clients.otx import OTXClient
from ..api_clients.transformers import transform_abuse, transform_otx, transform_vt
from ..api_clients.vt import VirusTotalClient
from ..cache import cache_provider
from ..config import get_settings
from ..logging_config import logger
from ..utils.rate_limiter import rate_limiter

try:  # optional dependency
    import dns.resolver  # type: ignore
except Exception:  # pragma: no cover
    dns = None  # type: ignore

settings = get_settings()
SUPPORTED_TYPES = {"ip", "domain", "url"}


@dataclass
class AggregatedResult:
    indicator_type: str
    value: str
    resolved_ips: List[str]
    source_results: Dict[str, Dict[str, Any]]
    aggregated_summary: Dict[str, Any]
    missing_api_keys: List[str]
    cached: bool

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["type"] = payload.pop("indicator_type")
        return payload


class IndicatorValidationError(ValueError):
    """Raised when an indicator value fails validation."""


def _normalise_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise IndicatorValidationError("Invalid IP address") from exc


def _normalise_domain(value: str) -> str:
    candidate = value.strip().lower()
    if "." not in candidate:
        raise IndicatorValidationError("Domain must include at least one dot")
    if candidate.startswith("http://") or candidate.startswith("https://"):
        raise IndicatorValidationError("Domain should not include scheme")
    return candidate


def _normalise_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if not parsed.scheme or not parsed.netloc:
        raise IndicatorValidationError("URL must include scheme and host")
    return value.strip()


def normalise_indicator(indicator_type: str, value: str) -> str:
    indicator_type = indicator_type.lower()
    if indicator_type == "ip":
        return _normalise_ip(value)
    if indicator_type == "domain":
        return _normalise_domain(value)
    if indicator_type == "url":
        return _normalise_url(value)
    raise IndicatorValidationError("Unsupported indicator type")


async def _resolve_dns_records(indicator_type: str, value: str) -> List[str]:
    if indicator_type != "domain" or not settings.enable_dns_resolve or dns is None:  # type: ignore[attr-defined]
        return []
    try:
        answers = dns.resolver.resolve(value, "A")  # type: ignore[attr-defined]
        return [answer.to_text() for answer in answers]
    except Exception:
        return []


async def _safe_fetch(client, indicator: str) -> Dict[str, Any]:
    try:
        return await client.fetch(indicator)
    except ThreatClientError:
        logger.info("ti.fallback", provider=client.name, indicator=indicator)
        return client.load_mock(indicator)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("ti.fetch_error", provider=client.name, indicator=indicator, error=str(exc))
        return client.load_mock(indicator)


def _summarise_vt(raw: Dict[str, Any]) -> Dict[str, Any]:
    transformed = transform_vt(raw)
    return {
        "malicious_count": transformed.get("malicious_count", 0),
        "suspicious_count": transformed.get("suspicious_count", 0),
        "reputation": transformed.get("reputation", 0),
        "summary": transformed.get("summary", ""),
    }


def _summarise_otx(raw: Dict[str, Any]) -> Dict[str, Any]:
    transformed = transform_otx(raw)
    return {
        "pulse_count": transformed.get("pulse_count", 0),
        "references": transformed.get("reference_count", 0),
        "summary": transformed.get("summary", ""),
    }


def _summarise_abuse(raw: Dict[str, Any]) -> Dict[str, Any]:
    transformed = transform_abuse(raw)
    return {
        "abuse_score": transformed.get("abuse_score", 0),
        "total_reports": transformed.get("total_reports", 0),
        "summary": transformed.get("summary", ""),
    }


def _evaluate_malicious(source_results: Dict[str, Dict[str, Any]]) -> Tuple[bool, List[str], str]:
    vt = source_results.get("virustotal", {})
    otx = source_results.get("otx", {})
    abuse = source_results.get("abuseipdb", {})

    malicious_sources: List[str] = []
    vt_malicious = vt.get("data", {}).get("malicious_count", 0)
    otx_pulses = otx.get("data", {}).get("pulse_count", 0)
    abuse_score = abuse.get("data", {}).get("abuse_score", 0)

    if vt_malicious >= 3 or abuse_score >= 90:
        malicious_sources.append("high-confidence")
    if vt_malicious >= 1:
        malicious_sources.append("virustotal")
    if otx_pulses >= 1:
        malicious_sources.append("otx")
    if abuse_score >= 50:
        malicious_sources.append("abuseipdb")

    is_malicious = bool(malicious_sources)
    summary_parts = []
    if vt_malicious:
        summary_parts.append(f"VT malicious={vt_malicious}")
    if otx_pulses:
        summary_parts.append(f"OTX pulses={otx_pulses}")
    if abuse_score:
        summary_parts.append(f"Abuse score={abuse_score}")
    summary_text = "; ".join(summary_parts) if summary_parts else "No malicious indicators detected."
    return is_malicious, malicious_sources, summary_text


async def lookup_indicator(
    indicator_type: str,
    value: str,
    *,
    user_id: str,
) -> AggregatedResult:
    if indicator_type not in SUPPORTED_TYPES:
        raise IndicatorValidationError("Unsupported indicator type")

    normalised = normalise_indicator(indicator_type, value)
    cache_key = f"ti:{indicator_type}:{normalised}"
    cached = await cache_provider.get(cache_key)
    if cached:
        payload = json.loads(cached.value if hasattr(cached, "value") else cached)
        payload["cached"] = True
        return AggregatedResult(
            indicator_type=payload["type"],
            value=payload["value"],
            resolved_ips=payload.get("resolved_ips", []),
            source_results=payload.get("source_results", {}),
            aggregated_summary=payload.get("aggregated_summary", {}),
            missing_api_keys=payload.get("missing_api_keys", []),
            cached=True,
        )

    if not await rate_limiter.check(f"ti:{user_id}"):
        raise IndicatorValidationError("Rate limit exceeded")

    resolved_ips = await _resolve_dns_records(indicator_type, normalised)
    vt_key = settings.vt_api_key
    otx_key = settings.otx_api_key
    abuse_key = settings.abuse_api_key

    missing_keys: List[str] = []
    vt_raw: Dict[str, Any]
    otx_raw: Dict[str, Any]
    abuse_raw: Dict[str, Any]

    if indicator_type == "ip":
        vt_client = VirusTotalClient(vt_key)
        otx_client = OTXClient(otx_key)
        abuse_client = AbuseIPDBClient(abuse_key)
        vt_raw = await _safe_fetch(vt_client, normalised) if vt_key else vt_client.load_mock(normalised)
        otx_raw = await _safe_fetch(otx_client, normalised) if otx_key else otx_client.load_mock(normalised)
        abuse_raw = await _safe_fetch(abuse_client, normalised) if abuse_key else abuse_client.load_mock(normalised)
        if not vt_key:
            missing_keys.append("VT_API_KEY")
        if not otx_key:
            missing_keys.append("OTX_API_KEY")
        if not abuse_key:
            missing_keys.append("ABUSE_API_KEY")
    else:
        # For domain/url we use lightweight simulated payloads to avoid outbound calls.
        vt_raw = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70},
                    "reputation": 0,
                }
            }
        }
        otx_raw = {"pulse_info": {"count": 0, "pulses": []}}
        abuse_raw = {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
        if not vt_key:
            missing_keys.append("VT_API_KEY")
        if indicator_type == "ip" and not otx_key:
            missing_keys.append("OTX_API_KEY")
        missing_keys = list({*missing_keys})

    source_results = {
        "virustotal": {"provider": "virustotal", "data": _summarise_vt(vt_raw)},
        "otx": {"provider": "otx", "data": _summarise_otx(otx_raw)},
        "abuseipdb": {"provider": "abuseipdb", "data": _summarise_abuse(abuse_raw)},
    }

    is_malicious, malicious_sources, summary_text = _evaluate_malicious(source_results)
    aggregated_summary = {
        "is_malicious": is_malicious,
        "malicious_sources": malicious_sources,
        "summary_text": summary_text,
    }

    result = AggregatedResult(
        indicator_type=indicator_type,
        value=normalised,
        resolved_ips=resolved_ips,
        source_results=source_results,
        aggregated_summary=aggregated_summary,
        missing_api_keys=missing_keys,
        cached=False,
    )

    await cache_provider.set(cache_key, json.dumps(result.to_dict()), ex=settings.ti_cache_ttl_seconds)
    return result
