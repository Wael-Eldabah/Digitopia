"""Software-only simulation / demo — no real systems will be contacted or modified."""
from backend.utils.rules import compute_verdict


def test_compute_verdict_high():
    vt = {"malicious_count": 3}
    otx = {"pulse_count": 0}
    abuse = {"abuse_score": 10}
    severity, action, rationale = compute_verdict(vt, otx, abuse)
    assert severity == "High"
    assert action == "Block"
    assert "High risk" in rationale


def test_compute_verdict_medium():
    vt = {"malicious_count": 1}
    otx = {"pulse_count": 12}
    abuse = {"abuse_score": 40}
    severity, action, _ = compute_verdict(vt, otx, abuse)
    assert severity == "Medium"
    assert action == "Monitor"


def test_compute_verdict_low():
    vt = {"malicious_count": 0}
    otx = {"pulse_count": 1}
    abuse = {"abuse_score": 20}
    severity, action, _ = compute_verdict(vt, otx, abuse)
    assert severity == "Low"
    assert action == "Notify"
