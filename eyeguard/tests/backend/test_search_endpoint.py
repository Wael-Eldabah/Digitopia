"""Software-only simulation / demo — no real systems will be contacted or modified."""
def test_search_returns_mock_data(client):
    response = client.get("/api/v1/search", params={"ip": "192.0.2.10"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["ip"] == "192.0.2.10"
    assert payload["computed_verdict"]["severity"] in {"Low", "Medium", "High", "Critical"}
    assert response.headers["X-Cache-Hit"] == "0"

    cached_response = client.get("/api/v1/search", params={"ip": "192.0.2.10"})
    assert cached_response.headers["X-Cache-Hit"] == "1"
