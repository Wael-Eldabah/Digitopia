"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from typing import Any


def transform_vt(data: dict[str, Any]) -> dict[str, Any]:
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    total = malicious + suspicious + harmless
    summary = f"{malicious} malicious / {suspicious} suspicious out of {total} analyses"
    return {
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "summary": summary,
    }


def transform_otx(data: dict[str, Any]) -> dict[str, Any]:
    pulses = data.get("pulse_info", {}).get("count", 0)
    references = len(data.get("pulse_info", {}).get("pulses", []))
    summary = f"Seen in {pulses} pulses with {references} references"
    return {
        "pulse_count": int(pulses),
        "reference_count": int(references),
        "summary": summary,
    }


def transform_abuse(data: dict[str, Any]) -> dict[str, Any]:
    data_block = data.get("data", data)
    score = int(data_block.get("abuseConfidenceScore", data_block.get("abuse_score", 0)))
    total_reports = int(data_block.get("totalReports", data_block.get("total_reports", 0)))
    summary = f"Abuse score {score} based on {total_reports} reports"
    return {
        "abuse_score": score,
        "total_reports": total_reports,
        "summary": summary,
    }


def transform_shodan(data: dict[str, Any]) -> dict[str, Any]:
    block = data.get("data", data) if isinstance(data, dict) else {}
    ports = sorted({int(port) for port in block.get("ports", []) if isinstance(port, (int, str))})
    tags = [str(tag) for tag in block.get("tags", [])][:10]
    vulns = [str(cve) for cve in block.get("vulns", [])][:20]
    service_names: list[str] = []
    services = block.get("services")
    if isinstance(services, list):
        for entry in services:
            if isinstance(entry, dict):
                name = entry.get("product") or entry.get("_shodan", {}).get("module")
                if name:
                    service_names.append(str(name))
    service_names = service_names[:10]
    tag_risk = any(tag.lower() in {"ransomware", "malware", "ics", "critical"} for tag in tags)
    exposure_score = min(100, len(ports) * 10 + len(vulns) * 15 + (20 if tag_risk else 0))
    summary_parts: list[str] = []
    if ports:
        preview = ", ".join(str(port) for port in ports[:5])
        summary_parts.append(f"Ports: {preview}{'...' if len(ports) > 5 else ''}")
    if vulns:
        summary_parts.append(f"CVE matches: {len(vulns)}")
    if tags:
        summary_parts.append(f"Tags: {', '.join(tags[:3])}{'...' if len(tags) > 3 else ''}")
    summary = "; ".join(summary_parts) if summary_parts else "No exposed services detected"
    return {
        "ports": ports,
        "tags": tags,
        "vulns": vulns,
        "services": service_names,
        "summary": summary,
        "risk": exposure_score,
        "organization": block.get("org") or block.get("isp"),
        "last_update": block.get("last_update") or block.get("last_seen"),
    }
