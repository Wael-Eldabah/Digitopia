"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ..models.schemas import (
    ActivityLog,
    Alert,
    Device,
    Report,
    SimulationDevice,
    User,
    UserPreferences,
)

STATIC_PROFILE_ROOT = os.path.join(os.path.dirname(__file__), "..", "static", "profile")


class DualModeLock:
    """Asyncio lock with optional synchronous context support for tests."""

    def __init__(self) -> None:
        self._async_lock = asyncio.Lock()

    def __enter__(self) -> "DualModeLock":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        return False

    async def __aenter__(self) -> "DualModeLock":
        await self._async_lock.acquire()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        self._async_lock.release()


class StateStore:
    def __init__(self) -> None:
        self._lock = DualModeLock()
        self.devices: Dict[str, Device] = {}
        self.alerts: Dict[str, Alert] = {}
        self.alert_audit: Dict[str, List[Dict[str, Any]]] = {}
        self.reports: Dict[str, Report] = {}
        self.sessions: Dict[str, SimulationDevice] = {}
        self.session_context: Dict[str, Dict[str, Any]] = {}
        self.pending_users: Dict[str, Dict[str, Any]] = {}
        self.users: Dict[str, User] = {}
        self.user_credentials: Dict[str, str] = {}
        self.session_tokens: Dict[str, str] = {}
        self.password_reset_tokens: Dict[str, Dict[str, Any]] = {}
        self.file_hashes: Dict[str, str] = {}
        self.profile_images: Dict[str, Optional[str]] = {}
        self.activity_logs: List[ActivityLog] = []
        self._seed()

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def _seed(self) -> None:
        os.makedirs(os.path.abspath(STATIC_PROFILE_ROOT), exist_ok=True)
        now = datetime.utcnow()
        device_id = str(uuid.uuid4())
        device = Device(
            id=device_id,
            ip_address="192.0.2.10",
            hostname="core-router",
            device_type="Router",
            owner_role="SOC_ANALYST",
            traffic_gb=2.5,
            traffic_delta=0.0,
            status="online",
            last_seen_at=now,
        )
        alert_id = str(uuid.uuid4())
        alert_detected = now - timedelta(hours=1)
        alert = Alert(
            id=alert_id,
            source_ip=device.ip_address,
            destination_ip="203.0.113.5",
            category="Suspicious Connection",
            severity="Medium",
            status="Open",
            detected_at=alert_detected,
            action_taken=None,
            rationale="Unexpected outbound connection to monitored IP.",
        )
        report_id = str(uuid.uuid4())
        report = Report(
            id=report_id,
            alert_id=alert_id,
            summary="Review suspicious connection from core-router.",
            remediation_steps="Blocked outbound traffic temporarily.",
            indicators=["192.0.2.10", "203.0.113.5"],
        )
        session_id = str(uuid.uuid4())
        simulation_device = SimulationDevice(session_id=session_id, device=device)
        manager_id = str(uuid.uuid4())
        manager = User(
            id=manager_id,
            email="wael@eyeguard.com",
            role="MANAGER",
            status="active",
            display_name="Wael Ashraf",
            avatar_seed="manager-root",
            profile_image_url=None,
            notifications=UserPreferences(),
        )

        self.devices[device_id] = device
        self.register_alert(alert, actor="system", event="Alert seeded during boot")
        self.reports[report_id] = report
        self.sessions[session_id] = simulation_device
        self.session_context[session_id] = {
            "cwd": "/",
            "device_id": device_id,
            "traffic_gb": device.traffic_gb,
            "auto_block": False,
            "files": {
                "/etc/config.txt": "interface=up\nmtu=1500\n",
                "/logs/auth.log": "[seed] auth service rotating keys\n",
            },
        }
        self.file_hashes["/etc/config.txt"] = hashlib.sha256(b"initial").hexdigest()
        self.users[manager.id] = manager
        self.profile_images[manager.id] = None
        self.user_credentials[manager.id] = self._hash_password("eyeguard")

    # ------------------------------------------------------------------
    # Authentication helpers
    # ------------------------------------------------------------------
    def authenticate(self, email: str, password: str) -> User | None:
        hashed = self._hash_password(password)
        for user_id, user in self.users.items():
            if user.email.lower() == email.lower() and self.user_credentials.get(user_id) == hashed:
                return user
        return None

    def issue_session_token(self, user_id: str) -> str:
        token = secrets.token_hex(16)
        for existing_token, existing_user_id in list(self.session_tokens.items()):
            if existing_user_id == user_id:
                self.session_tokens.pop(existing_token, None)
        self.session_tokens[token] = user_id
        return token

    def resolve_session_token(self, token: str) -> Optional[User]:
        user_id = self.session_tokens.get(token)
        if not user_id:
            return None
        return self.users.get(user_id)

    def revoke_session_token(self, token: str) -> None:
        self.session_tokens.pop(token, None)

    def issue_password_reset_token(self, user_id: str) -> str:
        token = secrets.token_urlsafe(18)
        self.password_reset_tokens[user_id] = {
            "token": token,
            "issued_at": datetime.utcnow().isoformat(),
        }
        return token

    def reset_user_password(self, user_id: str, new_password: str) -> None:
        self.user_credentials[user_id] = self._hash_password(new_password)
        self.log_activity(user_id, "user.password.reset", {"user_id": user_id})

    def delete_user(self, user_id: str) -> None:
        self.users.pop(user_id, None)
        self.user_credentials.pop(user_id, None)
        self.profile_images.pop(user_id, None)
        for token, owner in list(self.session_tokens.items()):
            if owner == user_id:
                self.session_tokens.pop(token, None)
        self.log_activity(user_id, "user.deleted", {"user_id": user_id})

    def set_user_status(self, user_id: str, status: str) -> User:
        updated = self.update_user(user_id, status=status)
        self.log_activity(user_id, "user.status.update", {"user_id": user_id, "status": status})
        return updated

    def email_exists(self, email: str) -> bool:
        lowered = email.lower()
        return any(user.email.lower() == lowered for user in self.users.values())

    def pending_email_exists(self, email: str) -> bool:
        lowered = email.lower()
        return any(entry.get("email", "").lower() == lowered for entry in self.pending_users.values())

    def find_user_id_by_email(self, email: str) -> Optional[str]:
        lowered = email.lower()
        for user_id, user in self.users.items():
            if user.email.lower() == lowered:
                return user_id
        return None

    # ------------------------------------------------------------------
    # User management helpers
    # ------------------------------------------------------------------
    def update_user(self, user_id: str, **fields: Any) -> User:
        user = self.users[user_id]
        payload = user.model_dump()
        if "email" in fields and fields["email"]:
            proposed = fields["email"].lower()
            if proposed != user.email.lower() and self.email_exists(proposed):
                raise ValueError("Email already in use")
            payload["email"] = fields["email"]
        for key, value in fields.items():
            if key != "email" and value is not None:
                payload[key] = value
        updated = User(**payload)
        self.users[user_id] = updated
        return updated

    def set_user_notifications(self, user_id: str, preferences: UserPreferences) -> User:
        return self.update_user(user_id, notifications=preferences)

    def set_profile_image(self, user_id: str, url: str | None) -> User:
        self.profile_images[user_id] = url
        return self.update_user(user_id, profile_image_url=url)

    def random_avatar_seed(self) -> str:
        return secrets.token_hex(8)

    # ------------------------------------------------------------------
    # Alert timeline helpers
    # ------------------------------------------------------------------
    def register_alert(self, alert: Alert, actor: str, event: str) -> None:
        self.alerts[alert.id] = alert
        self.alert_audit[alert.id] = [
            {
                "timestamp": alert.detected_at,
                "event": event,
                "actor": actor,
                "status": alert.status,
                "severity": alert.severity,
            }
        ]

    def append_alert_event(self, alert_id: str, event: str, actor: str, status: str, severity: str) -> None:
        history = self.alert_audit.setdefault(alert_id, [])
        history.append(
            {
                "timestamp": datetime.utcnow(),
                "event": event,
                "actor": actor,
                "status": status,
                "severity": severity,
            }
        )

    def get_alert_history(self, alert_id: str) -> List[Dict[str, Any]]:
        return self.alert_audit.get(alert_id, [])

    # ------------------------------------------------------------------
    # Activity logging
    # ------------------------------------------------------------------
    def log_activity(self, actor: str, event: str, metadata: Dict[str, Any]) -> None:
        entry = ActivityLog(
            id=str(uuid.uuid4()),
            actor=actor,
            event=event,
            metadata=metadata,
            created_at=datetime.utcnow(),
        )
        self.activity_logs.append(entry)
        if len(self.activity_logs) > 250:
            self.activity_logs = self.activity_logs[-250:]


state_store = StateStore()
