"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

from typing import Any


def compute_verdict(vt: dict[str, Any], otx: dict[str, Any], abuse: dict[str, Any], shodan: dict[str, Any] | None = None) -> tuple[str, str, str]:
    vt_malicious = vt.get("malicious_count", 0)
    abuse_score = abuse.get("abuse_score", 0)
    otx_pulses = otx.get("pulse_count", 0)
    shodan = shodan or {}
    shodan_risk = shodan.get("risk", 0)
    shodan_ports = len(shodan.get("exposed_ports", []))
    shodan_vulns = len(shodan.get("vulns", []))

    if shodan_risk >= 90 or shodan_ports >= 8 or shodan_vulns >= 5 or abuse_score >= 95 or vt_malicious >= 5:
        return ("Critical", "Contain", "Critical exposure detected via Shodan or multiple high-confidence feeds.")
    if abuse_score >= 85 or vt_malicious >= 3 or otx_pulses >= 12 or shodan_risk >= 70 or shodan_ports >= 5:
        return ("High", "Block", "High risk based on combined threat intelligence and exposed services.")
    if abuse_score >= 50 or vt_malicious >= 1 or otx_pulses >= 3 or shodan_risk >= 45 or shodan_ports >= 2:
        return ("Medium", "Monitor", "Elevated activity observed across intelligence sources or attack surface.")
    return ("Low", "Notify", "Indicators below critical thresholds.")
