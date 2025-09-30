"""Software-only simulation / demo - no real systems will be contacted or modified."""

def test_ip_lookup_returns_data(client):
    response = client.get('/api/search/ip', params={'ip': '192.0.2.10'})
    assert response.status_code == 200
    payload = response.json()
    assert payload['ip'] == '192.0.2.10'
    assert 'source_results' in payload
    assert 'aggregated_summary' in payload
    assert 'shodan' in payload['source_results']
    assert 'shodan_summary' in payload
    assert 'shodan_risk' in payload


def test_ip_lookup_invalid_ip(client):
    response = client.get('/api/search/ip', params={'ip': 'not-an-ip'})
    assert response.status_code == 400

def test_ip_lookup_google_dns(client):
    response = client.get('/api/search/ip', params={'ip': '8.8.8.8'})
    assert response.status_code == 200
    payload = response.json()
    assert payload['ip'] == '8.8.8.8'
    vt = payload['source_results']['virustotal']['data']
    shodan = payload['source_results']['shodan']['data']
    assert vt['malicious_count'] == 0
    assert shodan['risk'] == 10


def test_url_lookup_returns_summary(client):
    response = client.get('/api/search/indicator', params={'value': 'https://example.com', 'indicator_type': 'url'})
    assert response.status_code == 200
    payload = response.json()
    assert payload['value'] == 'https://example.com'
    assert 'aggregated_summary' in payload
