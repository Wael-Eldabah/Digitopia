"""Software-only simulation / demo — no real systems will be contacted or modified."""
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
