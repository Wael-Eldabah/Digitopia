"""Software-only simulation / demo - no real systems will be contacted or modified."""

def test_ip_lookup_returns_data(client):
    response = client.get('/api/search/ip', params={'ip': '192.0.2.10'})
    assert response.status_code == 200
    payload = response.json()
    assert payload['ip'] == '192.0.2.10'
    assert 'source_results' in payload
    assert 'aggregated_summary' in payload


def test_ip_lookup_invalid_ip(client):
    response = client.get('/api/search/ip', params={'ip': 'not-an-ip'})
    assert response.status_code == 400
