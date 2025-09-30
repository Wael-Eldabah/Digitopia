"""Software-only simulation / demo - no real systems will be contacted or modified."""
from backend.utils.rules import compute_verdict



def test_compute_verdict_critical():
    vt = {"malicious_count": 5}
    otx = {"pulse_count": 0}
    abuse = {"abuse_score": 40}
    shodan = {"risk": 95, "exposed_ports": [22, 3389, 445, 5985, 23, 80, 443, 3306]}
    severity, action, rationale = compute_verdict(vt, otx, abuse, shodan)
    assert severity == "Critical"
    assert action == "Contain"
    assert "Critical" in rationale



def test_compute_verdict_high():
    vt = {"malicious_count": 3}
    otx = {"pulse_count": 0}
    abuse = {"abuse_score": 10}
    shodan = {"risk": 60, "exposed_ports": [22, 443, 8080]}
    severity, action, rationale = compute_verdict(vt, otx, abuse, shodan)
    assert severity == "High"
    assert action == "Block"
    assert "High risk" in rationale



def test_compute_verdict_medium():
    vt = {"malicious_count": 1}
    otx = {"pulse_count": 5}
    abuse = {"abuse_score": 40}
    shodan = {"risk": 35}
    severity, action, _ = compute_verdict(vt, otx, abuse, shodan)
    assert severity == "Medium"
    assert action == "Monitor"



def test_compute_verdict_low():
    vt = {"malicious_count": 0}
    otx = {"pulse_count": 1}
    abuse = {"abuse_score": 20}
    shodan = {"risk": 10}
    severity, action, _ = compute_verdict(vt, otx, abuse, shodan)
    assert severity == "Low"
    assert action == "Notify"
