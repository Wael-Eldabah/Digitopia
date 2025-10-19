"""Software-only simulation / demo - no real systems will be contacted or modified."""
import uuid

from backend.models.schemas import User, UserPreferences
from backend.utils.state import state_store


def _provision_user(email: str, password: str, status: str = "active") -> User:
    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email=email,
        role="SOC_ANALYST",
        status=status,
        display_name=email.split("@", 1)[0].replace(".", " ").title(),
        avatar_seed="test-avatar",
        profile_image_url=None,
        notifications=UserPreferences(),
    )
    state_store.users[user_id] = user
    state_store.profile_images[user_id] = None
    state_store.reset_user_password(user_id, password)
    return user


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


def test_disabled_user_cannot_login(client):
    _provision_user('disabled@eyeguard.com', 'Secret123!', status='disabled')
    response = client.post('/api/v1/auth/login', json={'email': 'disabled@eyeguard.com', 'password': 'Secret123!'})
    assert response.status_code == 403
    detail = response.json().get('detail', {})
    assert detail.get('error_code') == 'ACCOUNT_DISABLED'


def test_disabled_user_session_revoked(client, manager_token):
    user = _provision_user('analyst@eyeguard.com', 'Secret123!')
    login = client.post('/api/v1/auth/login', json={'email': user.email, 'password': 'Secret123!'})
    assert login.status_code == 200
    token = login.json()['token']
    assert token in state_store.session_tokens

    disable_response = client.post(
        f'/api/v1/settings/users/{user.id}/status',
        json={'status': 'disabled'},
        headers={'X-Eyeguard-Token': manager_token},
    )
    assert disable_response.status_code == 200
    assert token not in state_store.session_tokens
    assert state_store.resolve_session_token(token) is None

    me_response = client.get('/api/v1/auth/me', headers={'X-Eyeguard-Token': token})
    assert me_response.status_code == 401

