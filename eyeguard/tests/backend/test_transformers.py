"""Software-only simulation / demo — no real systems will be contacted or modified."""
from backend.api_clients.transformers import transform_abuse, transform_otx, transform_shodan, transform_vt


def test_transform_vt_summary():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 4, "suspicious": 2, "harmless": 10}
            }
        }
    }
    result = transform_vt(payload)
    assert result["malicious_count"] == 4
    assert "4 malicious" in result["summary"]


def test_transform_otx_summary():
    payload = {"pulse_info": {"count": 12, "pulses": [1, 2, 3]}}
    result = transform_otx(payload)
    assert result["pulse_count"] == 12
    assert "12 pulses" in result["summary"]


def test_transform_abuse_summary():
    payload = {"data": {"abuseConfidenceScore": 70, "totalReports": 15}}
    result = transform_abuse(payload)
    assert result["abuse_score"] == 70
    assert "70" in result["summary"]

def test_transform_shodan_summary():
    payload = {
        "data": {
            "ports": [22, 3389, 445],
            "tags": ["ransomware", "test"],
            "vulns": ["CVE-2024-1234"],
            "org": "ExampleOrg",
        }
    }
    result = transform_shodan(payload)
    assert result["risk"] >= 30
    assert "Ports" in result["summary"]
    assert result["tags"]
