"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.app import app
from backend.cache import cache_provider
from backend.utils.state import StateStore, state_store


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    for key in ("VT_API_KEY", "OTX_API_KEY", "ABUSE_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    yield


@pytest.fixture(autouse=True)
def reset_cache():
    if hasattr(cache_provider, "_fallback"):
        cache_provider._fallback._store.clear()  # type: ignore[attr-defined]
    yield


@pytest.fixture(autouse=True)
def reset_state():
    fresh = StateStore()
    state_store.__dict__.clear()
    state_store.__dict__.update(fresh.__dict__)
    yield


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture()
def manager_token(client: TestClient) -> str:
    response = client.post('/api/v1/auth/login', json={'email': 'wael@eyeguard.com', 'password': 'eyeguard'})
    assert response.status_code == 200
    return response.json()['token']


@pytest.fixture()
def auth_headers(manager_token: str) -> dict[str, str]:
    return {'X-Eyeguard-Token': manager_token}
