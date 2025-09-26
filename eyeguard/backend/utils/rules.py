"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

from typing import Any


def compute_verdict(vt: dict[str, Any], otx: dict[str, Any], abuse: dict[str, Any]) -> tuple[str, str, str]:
    vt_malicious = vt.get("malicious_count", 0)
    abuse_score = abuse.get("abuse_score", 0)
    otx_pulses = otx.get("pulse_count", 0)

    if abuse_score >= 90 or vt_malicious >= 3:
        return ("High", "Block", "High risk based on VirusTotal or AbuseIPDB thresholds.")
    if otx_pulses >= 10 or abuse_score >= 50:
        return ("Medium", "Monitor", "Elevated activity observed across OTX or AbuseIPDB.")
    return ("Low", "Notify", "Indicators below critical thresholds.")
