"""Software-only simulation / demo - no real systems will be contacted or modified."""
from backend.utils.state import state_store


def test_login_success(client):
    response = client.post('/api/v1/auth/login', json={'email': 'wael@eyeguard.com', 'password': 'eyeguard'})
    assert response.status_code == 200
    data = response.json()
    assert data['user']['email'] == 'wael@eyeguard.com'
    assert 'token' in data
    assert state_store.resolve_session_token(data['token']) is not None


def test_login_failure(client):
    response = client.post('/api/v1/auth/login', json={'email': 'wael@eyeguard.com', 'password': 'wrongpass'})
    assert response.status_code == 401


def test_signup_stores_pending(client):
    payload = {
        'email': 'newuser@eyeguard.com',
        'password': 'validpass123',
        'role': 'SOC_ANALYST',
        'display_name': 'New User',
    }
    response = client.post('/api/v1/auth/signup', json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data['status'] == 'pending'
    assert data['request_id'] in state_store.pending_users
    pending = state_store.pending_users[data['request_id']]
    assert pending['display_name'] == 'New User'
    assert 'password_hash' in pending


def test_forgot_password_known_email(client):
    response = client.post('/api/v1/auth/forgot', json={'email': 'wael@eyeguard.com'})
    assert response.status_code == 200
    payload = response.json()
    assert 'reset_token' in payload
    assert any(entry.get('token') == payload['reset_token'] for entry in state_store.password_reset_tokens.values())


def test_me_endpoint_requires_token(client):
    response = client.get('/api/v1/auth/me')
    assert response.status_code == 422  # missing header


def test_me_endpoint_returns_user(client, manager_token):
    response = client.get('/api/v1/auth/me', headers={'X-Eyeguard-Token': manager_token})
    assert response.status_code == 200
    data = response.json()
    assert data['email'] == 'wael@eyeguard.com'

