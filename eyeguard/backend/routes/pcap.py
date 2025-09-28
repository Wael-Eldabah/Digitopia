"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import os
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from scapy.all import rdpcap, Packet, PcapReader  # Added for PCAP parsing
from scapy.layers.inet import IP

from ..config import get_settings
from ..logging_config import logger
from ..models.schemas import (
    Alert,
    PcapAnalysisDetail,
    PcapAnalysisSummary,
    PcapUploadResponse,
    Report,
    User,
)
from ..services import alerting, ti_aggregator
from ..utils.auth import get_current_user
from ..utils.ip_tools import normalize_ip
from ..utils.state import state_store

settings = get_settings()
router = APIRouter(prefix="/api/pcap", tags=["pcap"])

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_MAGIC_NUMBERS = {b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"}  # PCAP and PCAPNG

class PcapParsingError(Exception):
    pass

def validate_pcap_header(file_path: str) -> bool:
    """Validate the PCAP file's magic number to ensure it's a valid PCAP/PCAPNG file."""
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
            return magic in PCAP_MAGIC_NUMBERS
    except Exception as e:
        logger.warning("pcap.header_validation_failed", error=str(e))
        return False

def parse_pcap(file_path: str) -> Dict[str, Any]:
    """Parse a PCAP file and return a summary of its contents."""
    try:
        # Validate file header first
        if not validate_pcap_header(file_path):
            raise PcapParsingError("Invalid PCAP/PCAPNG header: incorrect magic number")

        packets = rdpcap(file_path)  # Use scapy to read PCAP/PCAPNG
        total_packets = len(packets)
        unique_ips = set()
        protocol_counts = {}
        ip_packet_counts = {}

        for pkt in packets:
            # Count protocols (simplified, assuming Ethernet + IP)
            if pkt.haslayer(IP):
                proto = pkt[IP].proto
                protocol_name = {6: "TCP", 17: "UDP"}.get(proto, f"Protocol_{proto}")
                protocol_counts[protocol_name] = protocol_counts.get(protocol_name, 0) + 1
                # Collect IPs
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                unique_ips.add(src_ip)
                unique_ips.add(dst_ip)
                ip_packet_counts[src_ip] = ip_packet_counts.get(src_ip, 0) + 1
                ip_packet_counts[dst_ip] = ip_packet_counts.get(dst_ip, 0) + 1

        # Sort IPs by packet count
        top_ips = [{"ip": ip, "packet_count": count} for ip, count in
                   sorted(ip_packet_counts.items(), key=lambda x: x[1], reverse=True)[:10]]

        return {
            "total_packets": total_packets,
            "unique_ips": list(unique_ips),
            "top_ips": top_ips,
            "protocol_counts": protocol_counts,
        }
    except Exception as e:
        raise PcapParsingError(f"Failed to parse PCAP file: {str(e)}")

def _ensure_upload_dir(user_id: str) -> str:
    uploads_root = os.path.abspath(settings.uploads_path)
    user_dir = os.path.join(uploads_root, user_id)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

@router.post("/upload", response_model=PcapUploadResponse)
async def upload_pcap(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
) -> PcapUploadResponse:
    # Validate file extension
    extension = os.path.splitext(file.filename or "")[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail={"ok": False, "error": "Only .pcap or .pcapng files are supported."})

    uploads_dir = _ensure_upload_dir(current_user.id)
    timestamp = int(time.time())
    safe_name = file.filename or f"capture{extension}"
    output_name = f"{timestamp}_{safe_name}"
    output_path = os.path.join(uploads_dir, output_name)

    # Save file with size limit check
    size_limit = settings.pcap_max_size_mb * 1024 * 1024
    total_bytes = 0
    try:
        with open(output_path, "wb") as destination:
            while chunk := await file.read(1024 * 1024):
                total_bytes += len(chunk)
                if total_bytes > size_limit:
                    await file.close()
                    os.remove(output_path)
                    raise HTTPException(status_code=400, detail={"ok": False, "error": f"PCAP exceeds size limit of {settings.pcap_max_size_mb} MB"})
                destination.write(chunk)
    except Exception as e:
        await file.close()
        if os.path.exists(output_path):
            os.remove(output_path)
        raise HTTPException(status_code=500, detail={"ok": False, "error": f"Failed to save file: {str(e)}"})
    finally:
        await file.close()

    # Parse the PCAP file
    try:
        summary = parse_pcap(output_path)
    except PcapParsingError as exc:
        logger.warning("pcap.parse_failed", error=str(exc))
        if os.path.exists(output_path):
            os.remove(output_path)
        raise HTTPException(status_code=400, detail={"ok": False, "error": f"Invalid PCAP file: {str(exc)}"})

    malicious_indicators: List[str] = []
    alerts_info: List[Dict[str, Any]] = []
    ip_payloads: List[Dict[str, Any]] = []

    enrichment_limit = max(settings.pcap_enrichment_ip_limit, 0)
    top_ip_entries = summary.get("top_ips", [])
    if not top_ip_entries and summary.get("unique_ips"):
        tentative_limit = enrichment_limit or 10
        top_ip_entries = [{"ip": ip, "packet_count": 0} for ip in summary["unique_ips"][:tentative_limit]]

    for index, entry in enumerate(top_ip_entries):
        ip = entry.get("ip")
        if not ip:
            continue
        packet_count = entry.get("packet_count", 0)
        normalized = normalize_ip(ip)
        payload = {
            "ip": normalized,
            "packet_count": packet_count,
            "source_results": {},
            "aggregated_summary": {
                "is_malicious": False,
                "malicious_sources": [],
                "summary_text": "Threat intelligence lookup not performed.",
            },
            "is_malicious": False,
            "severity": "Info",
        }

        should_enrich = enrichment_limit == 0 or index < enrichment_limit
        if should_enrich:
            try:
                result = await ti_aggregator.lookup_indicator("ip", normalized, user_id=current_user.id)
                verdict = result.aggregated_summary or {}
                payload["source_results"] = result.source_results
                payload["aggregated_summary"] = verdict
                payload["is_malicious"] = verdict.get("is_malicious", False)
                severity_label, stats = alerting.severity_from_sources(result.source_results)
                display_severity = "High" if "high-confidence" in verdict.get("malicious_sources", []) else ("Medium" if payload["is_malicious"] else "Info")
                payload["severity"] = display_severity
                if payload["is_malicious"]:
                    malicious_indicators.append(normalized)
                    message = alerting.build_alert_message(normalized, stats)
                    alerts_info.append({
                        "indicator": normalized,
                        "severity": severity_label.upper(),
                        "message": message,
                    })
            except Exception as exc:
                logger.warning("pcap.ti_lookup_failed", ip=normalized, error=str(exc))
        ip_payloads.append(payload)

    has_alerts = bool(malicious_indicators)
    report_summary = {
        "description": f"PCAP {safe_name} processed",
        "total_packets": summary.get("total_packets", 0),
        "unique_ips": len(summary.get("unique_ips", [])),
        "malicious_ips": len(malicious_indicators),
        "protocol_counts": summary.get("protocol_counts", {}),
    }

    created_at = datetime.utcnow()
    report_id = str(uuid.uuid4())

    analysis_record = {
        "id": report_id,
        "user_id": current_user.id,
        "created_at": created_at,
        "summary": report_summary,
        "ips": ip_payloads,
        "alerts": alerts_info,
        "has_alerts": has_alerts,
        "source_file": safe_name,
    }

    async with state_store._lock:  # type: ignore[attr-defined]
        state_store.save_pcap_analysis(analysis_record)
        state_store.reports[report_id] = Report(
            id=report_id,
            report_ref=report_id,
            user_id=current_user.id,
            type="pcap",
            title=f"PCAP Analysis - {safe_name}",
            source_filename=safe_name,
            has_alerts=has_alerts,
            created_at=created_at,
            summary=report_summary,
            cached=False,
        )
        actor = current_user.display_name or current_user.email
        for alert_entry in alerts_info:
            alert = Alert(
                id=str(uuid.uuid4()),
                detected_at=created_at,
                source_ip=alert_entry["indicator"],
                destination_ip=None,
                category="PCAP Malicious IP",
                severity=alert_entry["severity"].title(),
                status="Open",
                rationale=alert_entry["message"],
                action_taken=None,
            )
            state_store.register_alert(alert, actor=actor, event="pcap.analysis.alert")
            state_store.record_threat_alert({
                "id": str(uuid.uuid4()),
                "user_id": current_user.id,
                "indicator": alert.source_ip,
                "created_at": created_at,
                "severity": alert.severity,
                "sources": [alert_entry["severity"].lower()],
                "recommended_action": alert.action_taken or (alert.playbook or "Review PCAP response playbook"),
                "rationale": alert.rationale,
            })
        state_store.log_activity(
            actor=current_user.id,
            event="pcap.uploaded",
            metadata={
                "report_id": report_id,
                "file": safe_name,
                "total_packets": summary.get("total_packets", 0),
                "unique_ips": len(summary.get("unique_ips", [])),
                "malicious_ips": len(malicious_indicators),
            },
        )

    if has_alerts:
        recipients = state_store.collect_user_alert_targets(current_user)
        if recipients:
            lines = [f"- {entry['indicator']} ({entry['severity']}): {entry['message']}" for entry in alerts_info]
            body = "Malicious indicators detected in PCAP analysis:\n" + "\n".join(lines)
            state_store.send_email(
                subject="[EyeGuard] Malicious indicators detected in PCAP",
                body=body,
                recipients=recipients,
                category="pcap.alert",
                metadata={"report_id": report_id, "count": len(alerts_info)},
            )

    return PcapUploadResponse(
        ok=True,
        report_ref=report_id,
        has_alerts=has_alerts,
        summary=report_summary,
        ips=ip_payloads,
        alerts_triggered=alerts_info,
    )

@router.get("/analyses", response_model=List[PcapAnalysisSummary])
async def list_pcap_analyses(current_user: User = Depends(get_current_user)) -> List[PcapAnalysisSummary]:
    async with state_store._lock:  # type: ignore[attr-defined]
        analyses = state_store.list_pcap_analyses(current_user.id)
    return [PcapAnalysisSummary(**entry) for entry in analyses]

@router.get("/analyses/{analysis_id}", response_model=PcapAnalysisDetail)
async def get_pcap_analysis(analysis_id: str, current_user: User = Depends(get_current_user)) -> PcapAnalysisDetail:
    async with state_store._lock:  # type: ignore[attr-defined]
        analysis = state_store.get_pcap_analysis(analysis_id)
        if not analysis or analysis.get("user_id") != current_user.id:
            raise HTTPException(status_code=404, detail={"error_code": "ANALYSIS_NOT_FOUND", "message": "PCAP analysis not found"})
    return PcapAnalysisDetail(**analysis)