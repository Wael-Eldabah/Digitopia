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
from ..services.alerting import apply_alert_guidance

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
        self.threat_reports: Dict[str, Dict[str, Any]] = {}
        self.threat_alerts: Dict[str, Dict[str, Any]] = {}
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.simulation_states: Dict[str, Dict[str, Any]] = {}
        self.pcap_analyses: Dict[str, Dict[str, Any]] = {}
        self.integration_keys: Dict[str, Optional[str]] = {}
        self.outbound_email_log: List[Dict[str, Any]] = []
        self.integration_revision = 0
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
        report_summary = {
            "description": "Review suspicious connection from core-router.",
            "indicators": [device.ip_address, "203.0.113.5"],
        }
        report = Report(
            id=report_id,
            type="alert",
            title="Suspicious Connection Review",
            has_alerts=True,
            created_at=now,
            summary=report_summary,
            cached=False,
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
        target_role = payload.get("role") or user.role
        team_alerts = payload.get("team_alert_emails") if "team_alert_emails" in payload else user.team_alert_emails
        if target_role == "MANAGER" and team_alerts:
            preferences = payload.get("notifications") or user.notifications
            if isinstance(preferences, UserPreferences):
                pref_model = preferences
            else:
                pref_model = UserPreferences(**(preferences or {}))
            if not pref_model.critical_email:
                pref_model = UserPreferences(**{**pref_model.model_dump(), "critical_email": True})
            payload["notifications"] = pref_model
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
        enriched = apply_alert_guidance(alert)
        self.alerts[enriched.id] = enriched
        self.alert_audit[enriched.id] = [
            {
                "timestamp": enriched.detected_at,
                "event": event,
                "actor": actor,
                "status": enriched.status,
                "severity": enriched.severity,
            }
        ]
        if enriched.severity.lower() == "high":
            self._notify_malicious_alert(enriched)
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
    def find_alerts_by_ip(self, ip: str) -> List[Alert]:
        matches = [alert for alert in self.alerts.values() if alert.source_ip == ip or alert.destination_ip == ip]
        return [apply_alert_guidance(alert) for alert in matches]

    def find_devices_by_ip(self, ip: str) -> List[Device]:
        return [device for device in self.devices.values() if device.ip_address == ip]

    def recent_activity_for_indicator(self, ip: str) -> List[Dict[str, Any]]:
        timeline: List[Dict[str, Any]] = []
        for entry in reversed(self.activity_logs[-100:]):
            if not isinstance(entry.metadata, dict):
                continue
            metadata_ip = entry.metadata.get("ip")
            indicator = entry.metadata.get("indicator")
            if metadata_ip and metadata_ip != ip:
                continue
            if indicator and indicator != ip:
                continue
            if metadata_ip == ip or indicator == ip:
                timeline.append({
                    "id": entry.id,
                    "event": entry.event,
                    "actor": entry.actor,
                    "created_at": entry.created_at,
                    "metadata": entry.metadata,
                })
        return timeline


    # ------------------------------------------------------------------
    # Activity logging
    # ------------------------------------------------------------------
    def record_threat_report(self, report: Dict[str, Any]) -> None:
        self.threat_reports[report["id"]] = report

    def list_threat_reports(self, user_id: str) -> List[Dict[str, Any]]:
        reports = [entry for entry in self.threat_reports.values() if entry.get("user_id") == user_id]
        return sorted(reports, key=lambda item: item.get("created_at") or datetime.utcnow(), reverse=True)

    def get_threat_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        return self.threat_reports.get(report_id)

    def save_pcap_analysis(self, analysis: Dict[str, Any]) -> None:
        self.pcap_analyses[analysis["id"]] = analysis

    def list_pcap_analyses(self, user_id: str) -> List[Dict[str, Any]]:
        analyses = [entry for entry in self.pcap_analyses.values() if entry.get("user_id") == user_id]
        return sorted(analyses, key=lambda item: item.get("created_at") or datetime.utcnow(), reverse=True)

    def get_pcap_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        return self.pcap_analyses.get(analysis_id)

    def record_threat_alert(self, alert: Dict[str, Any]) -> None:
        self.threat_alerts[alert["id"]] = alert

    def list_threat_alerts(self, user_id: str) -> List[Dict[str, Any]]:
        alerts = [entry for entry in self.threat_alerts.values() if entry.get("user_id") == user_id]
        return sorted(alerts, key=lambda item: item.get("created_at") or datetime.utcnow(), reverse=True)

    def recent_unread_alerts(self, user_id: str) -> int:
        return sum(1 for alert in self.threat_alerts.values() if alert.get("user_id") == user_id and not alert.get("is_read"))

    def mark_threat_alert_read(self, user_id: str, alert_id: str) -> bool:
        alert = self.threat_alerts.get(alert_id)
        if not alert or alert.get("user_id") != user_id:
            return False
        alert["is_read"] = True
        return True

    def collect_user_alert_targets(self, user: User) -> List[str]:
        targets: List[str] = []
        if user.alert_email:
            targets.append(user.alert_email)
        else:
            targets.append(user.email)
        if user.role == "MANAGER":
            targets.extend(user.team_alert_emails or [])
        seen: set[str] = set()
        unique: List[str] = []
        for address in targets:
            if not address:
                continue
            lowered = address.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            unique.append(address)
        return unique

    def collect_global_alert_recipients(self) -> List[str]:
        recipients: List[str] = []
        for user in self.users.values():
            preferences = user.notifications or UserPreferences()
            if not preferences.critical_email:
                continue
            recipients.extend(self.collect_user_alert_targets(user))
        seen: set[str] = set()
        unique: List[str] = []
        for address in recipients:
            lowered = address.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            unique.append(address)
        return unique

    def _log_outbound_email(self, *, subject: str, body: str, recipients: List[str], category: str, metadata: Optional[Dict[str, Any]] | None = None) -> None:
        entry = {
            "id": str(uuid.uuid4()),
            "subject": subject,
            "body": body,
            "recipients": recipients,
            "category": category,
            "metadata": metadata or {},
            "created_at": datetime.utcnow(),
        }
        self.outbound_email_log.append(entry)
        if len(self.outbound_email_log) > 200:
            self.outbound_email_log = self.outbound_email_log[-200:]

    def send_email(self, *, subject: str, body: str, recipients: List[str], category: str, metadata: Optional[Dict[str, Any]] | None = None) -> None:
        self._log_outbound_email(subject=subject, body=body, recipients=recipients, category=category, metadata=metadata)

    def get_integration_keys(self) -> Dict[str, Optional[str]]:
        return {
            "vt_api_key": self.integration_keys.get("vt_api_key"),
            "otx_api_key": self.integration_keys.get("otx_api_key"),
            "abuse_api_key": self.integration_keys.get("abuse_api_key"),
        }

    def integration_keys_revision(self) -> int:
        return self.integration_revision

    def set_integration_keys(
        self, *, vt_api_key: Optional[str] = None, otx_api_key: Optional[str] = None, abuse_api_key: Optional[str] = None
    ) -> Dict[str, Optional[str]]:
        payload = {
            "vt_api_key": vt_api_key.strip() if isinstance(vt_api_key, str) and vt_api_key.strip() else None,
            "otx_api_key": otx_api_key.strip() if isinstance(otx_api_key, str) and otx_api_key.strip() else None,
            "abuse_api_key": abuse_api_key.strip() if isinstance(abuse_api_key, str) and abuse_api_key.strip() else None,
        }
        changed: Dict[str, str] = {}
        for key, value in payload.items():
            if value is None:
                if key in self.integration_keys:
                    self.integration_keys.pop(key, None)
                    changed[key] = "cleared"
            elif self.integration_keys.get(key) != value:
                self.integration_keys[key] = value
                changed[key] = "updated"
        if changed:
            self.integration_revision += 1
            self.log_activity("settings", "integration.keys.update", {"changes": changed})
        return self.get_integration_keys()

    def add_blocked_ip(self, ip: str, blocked_by: str) -> None:
        self.blocked_ips[ip] = {"ip": ip, "blocked_by": blocked_by, "created_at": datetime.utcnow()}
        self.log_activity(blocked_by, "blocklist.added", {"ip": ip})

    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def save_sim_state(self, user_id: str, state: Dict[str, Any]) -> None:
        self.simulation_states[user_id] = {"user_id": user_id, "state": state, "updated_at": datetime.utcnow()}

    def get_sim_state(self, user_id: str) -> Optional[Dict[str, Any]]:
        record = self.simulation_states.get(user_id)
        if record:
            return record.get("state")
        return None

    def clear_sim_state(self, user_id: str) -> None:
        self.simulation_states.pop(user_id, None)

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
