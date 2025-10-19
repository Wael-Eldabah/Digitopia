"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from ..models.schemas import (
    ActivityLog,
    Alert,
    Incident,
    IncidentDetail,
    IncidentTimelineEvent,
    Device,
    Report,
    SimulationDevice,
    User,
    UserPreferences,
)
from ..services.alerting import apply_alert_guidance
from ..services.threat_correlation import (
    CORRELATION_THRESHOLD,
    build_incident_summary,
    compute_incident_similarity,
    derive_incident_status,
    extract_behavioral_tags,
    highest_severity,
    severity_label,
    severity_rank,
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
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self.incident_audit: Dict[str, List[Dict[str, Any]]] = {}
        self.alert_to_incident: Dict[str, str] = {}
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
        self.blocklist_updated_at = datetime.utcnow()
        self.simulation_states: Dict[str, Dict[str, Any]] = {}
        self.pcap_analyses: Dict[str, Dict[str, Any]] = {}
        self.pcap_jobs: Dict[str, Dict[str, Any]] = {}
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
        user = self.users.get(user_id)
        if not user:
            self.session_tokens.pop(token, None)
            return None
        if user.status.lower() != "active":
            self.revoke_user_sessions(user_id)
            return None
        return user

    def revoke_session_token(self, token: str) -> None:
        self.session_tokens.pop(token, None)

    def revoke_user_sessions(self, user_id: str) -> None:
        for token, owner in list(self.session_tokens.items()):
            if owner == user_id:
                self.session_tokens.pop(token, None)

    def issue_password_reset_token(self, user_id: str) -> str:
        token = secrets.token_urlsafe(18)
        self.password_reset_tokens[user_id] = {
            "token": token,
            "issued_at": datetime.utcnow().isoformat(),
        }
        return token

    def validate_reset_token(self, email: str, token: str) -> Optional[str]:
        if not email or not token:
            return None
        user_id = self.find_user_id_by_email(email)
        if not user_id:
            return None
        record = self.password_reset_tokens.get(user_id)
        if not record:
            return None
        expected = record.get("token")
        if not expected or not secrets.compare_digest(str(expected), str(token)):
            return None
        self.password_reset_tokens.pop(user_id, None)
        return user_id

    def reset_user_password(self, user_id: str, new_password: str) -> None:
        self.user_credentials[user_id] = self._hash_password(new_password)
        self.log_activity(user_id, "user.password.reset", {"user_id": user_id})

    def delete_user(self, user_id: str) -> None:
        self.users.pop(user_id, None)
        self.user_credentials.pop(user_id, None)
        self.profile_images.pop(user_id, None)
        self.revoke_user_sessions(user_id)
        self.log_activity(user_id, "user.deleted", {"user_id": user_id})

    def set_user_status(self, user_id: str, status: str) -> User:
        updated = self.update_user(user_id, status=status)
        if updated.status.lower() != "active":
            self.revoke_user_sessions(user_id)
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
    def register_alert(self, alert: Alert, actor: str, event: str) -> Alert:
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
        incident = self._link_alert_to_incident(enriched, actor=actor)
        if incident:
            updated_alert = self.alerts[enriched.id]
            self.append_alert_event(
                enriched.id,
                f"Correlated with incident {incident['name']}",
                actor=actor,
                status=updated_alert.status,
                severity=updated_alert.severity,
            )
        final_alert = self.alerts[enriched.id]
        if final_alert.severity.lower() == "high":
            self._notify_malicious_alert(final_alert)
        return final_alert

    def _default_incident_name(self, alert: Alert) -> str:
        category = alert.category or "Threat"
        if alert.source_ip:
            return f"{category} Campaign [{alert.source_ip}]"
        if alert.destination_ip:
            return f"{category} Campaign → {alert.destination_ip}"
        return f"{category} Campaign"

    def _assign_alert_incident(self, alert_id: str, incident_id: str, context: Dict[str, Any]) -> Alert:
        alert = self.alerts[alert_id]
        payload = alert.model_dump()
        payload["incident_id"] = incident_id
        payload["incident_context"] = context
        updated = Alert(**payload)
        self.alerts[alert_id] = updated
        self.alert_to_incident[alert_id] = incident_id
        return updated

    def _update_incident_metrics(self, incident_id: str) -> Optional[Dict[str, Any]]:
        record = self.incidents.get(incident_id)
        if not record:
            return None
        alert_ids: List[str] = record.get("alert_ids", [])
        alerts = [self.alerts[alert_id] for alert_id in alert_ids if alert_id in self.alerts]
        if not alerts:
            record["alert_ids"] = []
            record["alert_count"] = 0
            record["status"] = "Closed"
            record["summary"] = "No correlated alerts recorded for this incident yet."
            record["severity_rank"] = severity_rank(record.get("severity"))
            record["severity"] = severity_label(record["severity_rank"])
            return record
        first_seen = min(alert.detected_at for alert in alerts)
        last_seen = max(alert.detected_at for alert in alerts)
        record["first_seen"] = first_seen
        record["last_seen"] = last_seen
        record["alert_ids"] = [alert.id for alert in alerts]
        record["alert_count"] = len(alerts)
        categories: Set[str] = set()
        categories_norm: Set[str] = set()
        category_tokens: Set[str] = set()
        source_ips: Set[str] = set()
        destination_ips: Set[str] = set()
        behavioural_tags: Set[str] = set()
        for entry in alerts:
            if entry.category:
                categories.add(entry.category)
                normalized = entry.category.strip().lower()
                if normalized:
                    categories_norm.add(normalized)
                    category_tokens.update(token for token in normalized.split() if token)
            if entry.source_ip:
                source_ips.add(entry.source_ip)
            if entry.destination_ip:
                destination_ips.add(entry.destination_ip)
            behavioural_tags.update(extract_behavioral_tags(entry))
        record["categories"] = categories
        record["categories_norm"] = categories_norm
        record["category_tokens"] = category_tokens
        record["source_ips"] = source_ips
        record["destination_ips"] = destination_ips
        record["behavioral_tags"] = behavioural_tags
        top_severity = highest_severity(alerts)
        record["severity"] = top_severity
        record["severity_rank"] = severity_rank(top_severity)
        record["status"] = derive_incident_status(alerts)
        record["lead_alert_id"] = min(alerts, key=lambda item: item.detected_at).id
        record["summary"] = build_incident_summary(record, alerts)
        return record

    def _build_incident_snapshot(self, incident_id: str) -> Optional[Incident]:
        record = self._update_incident_metrics(incident_id)
        if not record:
            return None
        return Incident(
            id=incident_id,
            name=record.get("name") or "Correlated Campaign",
            status=record.get("status") or "Active",
            severity=record.get("severity") or "Low",
            alert_count=record.get("alert_count", len(record.get("alert_ids", []))),
            first_seen=record.get("first_seen") or datetime.utcnow(),
            last_seen=record.get("last_seen") or datetime.utcnow(),
            categories=sorted(record.get("categories", [])),
            source_ips=sorted(record.get("source_ips", [])),
            destination_ips=sorted(record.get("destination_ips", [])),
            summary=record.get("summary"),
            lead_alert_id=record.get("lead_alert_id"),
        )

    def _propagate_incident_context(self, incident_id: str) -> Optional[Incident]:
        snapshot = self._build_incident_snapshot(incident_id)
        if not snapshot:
            return None
        context = {
            "incident_id": snapshot.id,
            "name": snapshot.name,
            "status": snapshot.status,
            "severity": snapshot.severity,
            "alert_count": snapshot.alert_count,
            "first_seen": snapshot.first_seen,
            "last_seen": snapshot.last_seen,
            "summary": snapshot.summary,
            "source_ips": snapshot.source_ips,
            "destination_ips": snapshot.destination_ips,
            "categories": snapshot.categories,
        }
        record = self.incidents.get(snapshot.id, {})
        for alert_id in record.get("alert_ids", []):
            if alert_id not in self.alerts:
                continue
            self._assign_alert_incident(alert_id, snapshot.id, context)
        return snapshot

    def _create_incident_from_alert(self, alert: Alert, actor: str, alert_tags: Set[str]) -> Dict[str, Any]:
        incident_id = str(uuid.uuid4())
        record: Dict[str, Any] = {
            "id": incident_id,
            "name": self._default_incident_name(alert),
            "status": "Active",
            "severity": alert.severity,
            "severity_rank": severity_rank(alert.severity),
            "first_seen": alert.detected_at,
            "last_seen": alert.detected_at,
            "alert_ids": [alert.id],
            "alert_count": 1,
            "categories": {alert.category} if alert.category else set(),
            "categories_norm": {alert.category.strip().lower()} if alert.category else set(),
            "category_tokens": {token for token in (alert.category or "").strip().lower().split() if token},
            "source_ips": {alert.source_ip} if alert.source_ip else set(),
            "destination_ips": {alert.destination_ip} if alert.destination_ip else set(),
            "behavioral_tags": set(alert_tags),
            "lead_alert_id": alert.id,
            "summary": None,
        }
        self.incidents[incident_id] = record
        self.incident_audit[incident_id] = [
            {
                "timestamp": alert.detected_at,
                "event": f"Incident created from alert {alert.category}",
                "actor": actor,
                "metadata": {"alert_id": alert.id, "severity": alert.severity},
            }
        ]
        snapshot = self._propagate_incident_context(incident_id)
        if snapshot:
            self.append_incident_event(
                incident_id,
                "Incident initialized",
                actor=actor,
                metadata={"alert_id": alert.id},
            )
        return self.incidents[incident_id]

    def _attach_alert_to_incident(self, incident_id: str, alert: Alert, actor: str, alert_tags: Set[str]) -> Dict[str, Any]:
        record = self.incidents.get(incident_id)
        if not record:
            return self._create_incident_from_alert(alert, actor=actor, alert_tags=alert_tags)
        record.setdefault("alert_ids", []).append(alert.id)
        if alert.category:
            record.setdefault("categories", set()).add(alert.category)
            normalized = alert.category.strip().lower()
            if normalized:
                record.setdefault("categories_norm", set()).add(normalized)
                record.setdefault("category_tokens", set()).update(token for token in normalized.split() if token)
        if alert.source_ip:
            record.setdefault("source_ips", set()).add(alert.source_ip)
        if alert.destination_ip:
            record.setdefault("destination_ips", set()).add(alert.destination_ip)
        record.setdefault("behavioral_tags", set()).update(alert_tags)
        snapshot = self._propagate_incident_context(incident_id)
        if snapshot:
            self.append_incident_event(
                incident_id,
                f"Alert {alert.category} linked",
                actor=actor,
                metadata={"alert_id": alert.id},
            )
        return self.incidents[incident_id]

    def _link_alert_to_incident(self, alert: Alert, actor: str) -> Optional[Dict[str, Any]]:
        alert_tags = extract_behavioral_tags(alert)
        best_incident_id: Optional[str] = None
        best_score = float("-inf")
        for incident_id, record in self.incidents.items():
            similarity = compute_incident_similarity(record, alert, alert_tags=alert_tags)
            if similarity > best_score:
                best_score = similarity
                best_incident_id = incident_id
        if best_incident_id and best_score >= CORRELATION_THRESHOLD:
            record = self._attach_alert_to_incident(best_incident_id, alert, actor=actor, alert_tags=alert_tags)
            self.append_incident_event(
                best_incident_id,
                f"Alert {alert.category} correlated (score {best_score:.2f})",
                actor=actor,
                metadata={"alert_id": alert.id, "score": round(best_score, 2)},
            )
            return record
        return self._create_incident_from_alert(alert, actor=actor, alert_tags=alert_tags)

    def append_incident_event(self, incident_id: str, event: str, actor: str, metadata: Optional[Dict[str, Any]] | None = None) -> None:
        history = self.incident_audit.setdefault(incident_id, [])
        history.append(
            {
                "timestamp": datetime.utcnow(),
                "event": event,
                "actor": actor,
                "metadata": metadata or {},
            }
        )
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

    def get_incident_history(self, incident_id: str) -> List[Dict[str, Any]]:
        return self.incident_audit.get(incident_id, [])

    def list_incidents(self) -> List[Incident]:
        snapshots: List[Incident] = []
        for incident_id in list(self.incidents.keys()):
            snapshot = self._propagate_incident_context(incident_id)
            if snapshot:
                snapshots.append(snapshot)
        snapshots.sort(key=lambda item: item.last_seen, reverse=True)
        return snapshots

    def get_incident_detail(self, incident_id: str) -> Optional[IncidentDetail]:
        snapshot = self._propagate_incident_context(incident_id)
        if not snapshot:
            return None
        record = self.incidents.get(incident_id, {})
        alerts: List[Alert] = []
        for alert_id in record.get("alert_ids", []):
            alert = self.alerts.get(alert_id)
            if not alert:
                continue
            alerts.append(apply_alert_guidance(alert))
        timeline = [
            IncidentTimelineEvent(
                timestamp=entry.get("timestamp") or datetime.utcnow(),
                event=entry.get("event", ""),
                actor=entry.get("actor", "system"),
                metadata=entry.get("metadata") or {},
            )
            for entry in self.incident_audit.get(incident_id, [])
        ]
        return IncidentDetail(**snapshot.model_dump(), alerts=alerts, timeline=timeline)

    def incident_id_for_alert(self, alert_id: str) -> Optional[str]:
        return self.alert_to_incident.get(alert_id)

    def refresh_incident_for_alert(self, alert_id: str, actor: Optional[str] = None, reason: Optional[str] = None) -> None:
        incident_id = self.alert_to_incident.get(alert_id)
        if not incident_id:
            return
        snapshot = self._propagate_incident_context(incident_id)
        if snapshot and reason:
            self.append_incident_event(
                incident_id,
                reason,
                actor=actor or "system",
                metadata={"alert_id": alert_id},
            )

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

    def upsert_pcap_job(self, job: Dict[str, Any]) -> None:
        self.pcap_jobs[job["id"]] = job

    def update_pcap_job(self, job_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        job = self.pcap_jobs.get(job_id)
        if not job:
            return None
        job.update(updates)
        job["updated_at"] = datetime.utcnow()
        return job

    def get_pcap_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        return self.pcap_jobs.get(job_id)

    def remove_pcap_job(self, job_id: str) -> bool:
        if job_id not in self.pcap_jobs:
            return False
        self.pcap_jobs.pop(job_id, None)
        return True

    def list_pcap_jobs(self, user_id: str) -> List[Dict[str, Any]]:
        jobs = [entry for entry in self.pcap_jobs.values() if entry.get("user_id") == user_id]
        return sorted(jobs, key=lambda item: item.get("created_at") or datetime.utcnow(), reverse=True)

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
            "shodan_api_key": self.integration_keys.get("shodan_api_key"),
            "mxtoolbox_api_key": self.integration_keys.get("mxtoolbox_api_key"),
        }

    def integration_keys_revision(self) -> int:
        return self.integration_revision

    def set_integration_keys(
        self,
        *,
        vt_api_key: Optional[str] = None,
        otx_api_key: Optional[str] = None,
        abuse_api_key: Optional[str] = None,
        shodan_api_key: Optional[str] = None,
        mxtoolbox_api_key: Optional[str] = None,
    ) -> Dict[str, Optional[str]]:
        payload = {
            "vt_api_key": vt_api_key.strip() if isinstance(vt_api_key, str) and vt_api_key.strip() else None,
            "otx_api_key": otx_api_key.strip() if isinstance(otx_api_key, str) and otx_api_key.strip() else None,
            "abuse_api_key": abuse_api_key.strip() if isinstance(abuse_api_key, str) and abuse_api_key.strip() else None,
            "shodan_api_key": shodan_api_key.strip() if isinstance(shodan_api_key, str) and shodan_api_key.strip() else None,
            "mxtoolbox_api_key": mxtoolbox_api_key.strip() if isinstance(mxtoolbox_api_key, str) and mxtoolbox_api_key.strip() else None,
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

    def add_blocked_ip(self, ip: str, blocked_by: str | None) -> bool:
        actor = blocked_by or 'system'
        existing = self.blocked_ips.get(ip)
        if existing:
            if blocked_by and existing.get("blocked_by") != blocked_by:
                existing["blocked_by"] = blocked_by
            return False
        created_at = datetime.utcnow()
        self.blocked_ips[ip] = {"ip": ip, "blocked_by": blocked_by, "created_at": created_at}
        self.blocklist_updated_at = created_at
        self.log_activity(actor, "blocklist.added", {"ip": ip})
        closed_alerts: List[str] = []
        for alert_id, alert in list(self.alerts.items()):
            if alert.source_ip == ip or alert.destination_ip == ip:
                if alert.status == "Closed":
                    continue
                updated = apply_alert_guidance(
                    alert.model_copy(
                        update={"status": "Closed", "auto_closed_by_system": True, "status_locked": True}
                    )
                )
                self.alerts[alert_id] = updated
                closed_alerts.append(alert_id)
                self.append_alert_event(
                    alert_id,
                    "Auto-closed due to blocklist",
                    actor=actor,
                    status=updated.status,
                    severity=updated.severity,
                )
                self.refresh_incident_for_alert(
                    alert_id,
                    actor=actor,
                    reason="Alert auto-closed due to blocklist",
                )
        if closed_alerts:
            self.log_activity(actor, "blocklist.auto_close_alerts", {"ip": ip, "alert_ids": closed_alerts})
        return True

    def remove_blocked_ip(self, ip: str, removed_by: Optional[str] | None = None) -> bool:
        if ip not in self.blocked_ips:
            return False
        self.blocked_ips.pop(ip, None)
        self.blocklist_updated_at = datetime.utcnow()
        if removed_by:
            self.log_activity(removed_by, "blocklist.removed", {"ip": ip})
        return True

    def list_blocked_ips(self) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        for data in self.blocked_ips.values():
            created_at = data.get("created_at")
            if isinstance(created_at, str):
                try:
                    created_dt = datetime.fromisoformat(created_at)
                except ValueError:
                    created_dt = datetime.utcnow()
            else:
                created_dt = created_at or datetime.utcnow()
            entries.append({"ip": data.get("ip"), "blocked_by": data.get("blocked_by"), "created_at": created_dt})
        entries.sort(key=lambda item: item.get("created_at") or datetime.utcnow(), reverse=True)
        return entries

    def sync_blocked_ips(self, records: List[Dict[str, Any]]) -> None:
        incoming: Dict[str, Dict[str, Any]] = {}
        for entry in records:
            ip_value = entry.get("ip")
            if not ip_value:
                continue
            created_at = entry.get("created_at")
            if isinstance(created_at, str):
                try:
                    created_dt = datetime.fromisoformat(created_at)
                except ValueError:
                    created_dt = datetime.utcnow()
            elif isinstance(created_at, datetime):
                created_dt = created_at
            else:
                created_dt = datetime.utcnow()
            incoming[ip_value] = {
                "ip": ip_value,
                "blocked_by": entry.get("blocked_by"),
                "created_at": created_dt,
            }

        current_ips = set(self.blocked_ips.keys())
        incoming_ips = set(incoming.keys())

        for ip in current_ips - incoming_ips:
            self.remove_blocked_ip(ip)

        for ip in incoming_ips - current_ips:
            payload = incoming[ip]
            added = self.add_blocked_ip(ip, payload.get("blocked_by"))
            if added:
                self.blocked_ips[ip]["created_at"] = payload.get("created_at")

        for ip in incoming_ips & current_ips:
            payload = incoming[ip]
            entry = self.blocked_ips[ip]
            entry["blocked_by"] = payload.get("blocked_by")
            entry["created_at"] = payload.get("created_at")

        if incoming_ips:
            latest = max(
                (self.blocked_ips[ip]["created_at"] for ip in incoming_ips if self.blocked_ips[ip].get("created_at")),
                default=datetime.utcnow(),
            )
            self.blocklist_updated_at = latest
        else:
            self.blocklist_updated_at = datetime.utcnow()

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
