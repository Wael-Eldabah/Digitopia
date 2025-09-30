"""Software-only simulation / demo - no real systems will be contacted or modified."""

def test_alert_status_update(client, auth_headers):
    alerts_response = client.get('/api/v1/alerts')
    assert alerts_response.status_code == 200
    payload = alerts_response.json()
    alert_list = payload['items'] if isinstance(payload, dict) else payload
    assert alert_list, 'expected at least one alert in seed data'
    alert_id = alert_list[0]['id']

    update_response = client.post(f'/api/v1/alerts/{alert_id}/status', json={'status': 'Acknowledged'}, headers=auth_headers)
    assert update_response.status_code == 200
    assert update_response.json()['status'] == 'Acknowledged'

    detail_response = client.get(f'/api/v1/alerts/{alert_id}')
    assert detail_response.status_code == 200
    timeline = detail_response.json()['events']
    assert any('Status changed to Acknowledged' in event['event'] for event in timeline)