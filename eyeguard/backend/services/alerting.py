"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

from ..services import emailer


def severity_from_sources(source_results: Dict[str, Dict[str, Dict[str, int]]]) -> Tuple[str, Dict[str, int]]:
    vt_data = source_results.get("virustotal", {}).get("data", {})
    otx_data = source_results.get("otx", {}).get("data", {})
    abuse_data = source_results.get("abuseipdb", {}).get("data", {})

    vt_malicious = vt_data.get("malicious_count", 0)
    otx_pulses = otx_data.get("pulse_count", 0)
    abuse_score = abuse_data.get("abuse_score", 0)

    if abuse_score >= 80 or vt_malicious >= 3:
        level = "high"
    elif vt_malicious >= 1 or otx_pulses >= 1 or abuse_score >= 50:
        level = "medium"
    else:
        level = "low"
    return level, {
        "vt_malicious": vt_malicious,
        "otx_pulses": otx_pulses,
        "abuse_score": abuse_score,
    }


def build_alert_message(indicator: str, stats: Dict[str, int]) -> str:
    parts: List[str] = []
    if stats["vt_malicious"]:
        parts.append(f"VT={stats['vt_malicious']}")
    if stats["otx_pulses"]:
        parts.append(f"OTX={stats['otx_pulses']}")
    if stats["abuse_score"]:
        parts.append(f"Abuse={stats['abuse_score']}")
    detail = ", ".join(parts) if parts else "No high confidence stats"
    return f"Malicious indicator detected: {indicator} ({detail})"


def dispatch_alert_email(recipients: Iterable[str], indicator: str, severity: str, message: str) -> None:
    subject = f"EyeGuard Alert ({severity.title()}): {indicator}"
    body = f"Severity: {severity}\nIndicator: {indicator}\nDetails: {message}\n"
    emailer.send_alert_email(recipients, subject, body)
