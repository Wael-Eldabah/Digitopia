"""Software-only simulation / demo — no real systems will be contacted or modified."""
from backend.utils.state import state_store


def test_terminal_cd_private_triggers_alert(client):
    payload = {"ip_address": "198.51.100.25", "hostname": "sim-host", "traffic_gb": 5.0, "device_type": "Server"}
    response = client.post("/api/v1/simulation/devices", json=payload)
    assert response.status_code == 201
    session_id = response.json()["session_id"]

    cd_response = client.post("/api/v1/simulation/terminal", json={"session_id": session_id, "command": "cd /private"})
    assert cd_response.status_code == 200
    triggered = cd_response.json()["alerts_triggered"]
    assert triggered
    assert any(alert["category"] == "Restricted Access" for alert in triggered)

    # Validate alert stored globally
    with state_store._lock:  # type: ignore[attr-defined]
        assert any(alert.category == "Restricted Access" for alert in state_store.alerts.values())

def test_nano_file_not_found(client):
    device_payload = {"ip_address": "198.51.100.45", "hostname": "nano-host", "traffic_gb": 1.0, "device_type": "Server"}
    session_response = client.post('/api/v1/simulation/devices', json=device_payload)
    assert session_response.status_code == 201
    session_id = session_response.json()['session_id']

    response = client.post('/api/v1/simulation/nano', json={"session_id": session_id, "file_path": "/etc/missing.cfg", "action": "open"})
    assert response.status_code == 200
    payload = response.json()
    assert payload['error'] == 'File not found'
