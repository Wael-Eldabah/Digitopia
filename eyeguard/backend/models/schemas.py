"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class BaseSchema(BaseModel):
    """Base schema with attribute extraction enabled."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class SystemHealth(BaseSchema):
    status: str
    components: Dict[str, str] = Field(default_factory=dict)


class Device(BaseSchema):
    id: str
    ip_address: str
    hostname: str
    device_type: str
    owner_role: str
    traffic_gb: float = 0.0
    traffic_delta: float = 0.0
    status: str = "online"
    last_seen_at: Optional[datetime] = None


class DeviceCreate(BaseSchema):
    ip_address: str
    hostname: str
    device_type: str
    owner_role: str
    traffic_gb: Optional[float] = None


class DeviceUpdate(BaseSchema):
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    owner_role: Optional[str] = None
    traffic_gb: Optional[float] = None
    status: Optional[str] = None


class Alert(BaseSchema):
    id: str
    detected_at: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    category: str
    severity: str
    status: str
    auto_closed_by_system: bool = False
    status_locked: bool = False
    rationale: Optional[str] = None
    action_taken: Optional[str] = None
    playbook: Optional[str] = None
    recommended_actions: List[str] = Field(default_factory=list)
    mitigation_steps: List[str] = Field(default_factory=list)
    intel_summary: Optional[str] = None
    on_blocklist: bool = False


class AlertCreate(BaseSchema):
    source_ip: str
    destination_ip: Optional[str] = None
    category: str
    severity: str
    rationale: Optional[str] = None
    playbook: Optional[str] = None
    recommended_actions: List[str] = Field(default_factory=list)
    mitigation_steps: List[str] = Field(default_factory=list)
    intel_summary: Optional[str] = None


class AlertStatusUpdate(BaseSchema):
    status: str


class AlertDetail(Alert):
    events: List[Dict[str, Any]] = Field(default_factory=list)


class Report(BaseSchema):
    id: str
    type: str
    title: str
    has_alerts: bool
    created_at: datetime
    summary: Dict[str, Any] = Field(default_factory=dict)
    cached: Optional[bool] = None


class ReportDetail(Report):
    payload: Dict[str, Any] = Field(default_factory=dict)


class SimulationDeviceCreate(BaseSchema):
    ip_address: str
    hostname: str
    traffic_gb: float
    device_type: Optional[str] = None


class SimulationDevice(BaseSchema):
    session_id: str
    device: Device
    status_message: Optional[str] = None
    blocked: bool = False


class TerminalCommandRequest(BaseSchema):
    session_id: str
    command: str


class TerminalCommandResponse(BaseSchema):
    output: str
    alerts_triggered: List[Alert] = Field(default_factory=list)


class NanoFileAction(BaseSchema):
    session_id: str
    file_path: str
    action: str
    contents: Optional[str] = None


class NanoFileResponse(BaseSchema):
    file_path: str
    contents: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None


class UserPreferences(BaseSchema):
    critical_email: bool = True
    weekly_digest: bool = True
    push: bool = False


class User(BaseSchema):
    id: str
    email: EmailStr
    role: str
    status: str
    display_name: Optional[str] = None
    avatar_seed: Optional[str] = None
    profile_image_url: Optional[str] = None
    alert_email: Optional[EmailStr] = None
    team_alert_emails: List[EmailStr] = Field(default_factory=list)
    notifications: UserPreferences = Field(default_factory=UserPreferences)


class UserProfileUpdate(BaseSchema):
    display_name: Optional[str] = None
    email: Optional[EmailStr] = None
    alert_email: Optional[EmailStr] = None
    team_alert_emails: Optional[List[EmailStr]] = None


class UserNotificationUpdate(BaseSchema):
    notifications: UserPreferences


class PcapUploadResponse(BaseSchema):
    ok: bool
    report_ref: str
    has_alerts: bool
    summary: Dict[str, Any] = Field(default_factory=dict)
    ips: List[Dict[str, Any]] = Field(default_factory=list)
    alerts_triggered: List[Dict[str, Any]] = Field(default_factory=list)


class PcapJobStatus(BaseSchema):
    id: str
    user_id: str
    status: str
    progress: int = 0
    stage: Optional[str] = None
    message: Optional[str] = None
    report_ref: Optional[str] = None
    alerts_generated: int = 0
    total_ips: int = 0
    filename: Optional[str] = None
    blocked_ips: List[str] = Field(default_factory=list)
    self_check: Dict[str, bool] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime



class IndicatorSearchResponse(BaseSchema):
    ok: bool = True
    type: str
    value: str
    resolved_ips: List[str] = Field(default_factory=list)
    source_results: Dict[str, Any] = Field(default_factory=dict)
    aggregated_summary: Dict[str, Any] = Field(default_factory=dict)
    missing_api_keys: List[str] = Field(default_factory=list)
    cached: bool = False
    has_alerts: bool = False
    malicious_sources: List[str] = Field(default_factory=list)
    intel_summary: Optional[str] = None
    report_ref: Optional[str] = None


class BlocklistRequest(BaseSchema):
    ip: str


class BlocklistEntry(BaseSchema):
    ip: str
    blocked_by: Optional[str] = None
    created_at: datetime


class BlocklistSnapshot(BaseSchema):
    count: int = 0
    items: List[str] = Field(default_factory=list)
    updated_at: datetime
    details: List[BlocklistEntry] = Field(default_factory=list)


class BlocklistResponse(BlocklistSnapshot):
    pass


class BlocklistStatusResponse(BaseSchema):
    blocked: bool


class BlocklistListResponse(BlocklistSnapshot):
    pass


class SimulationStatePayload(BaseSchema):
    state: Dict[str, Any] = Field(default_factory=dict)


class UserSettings(BaseSchema):
    name: Optional[str] = None
    role: str
    email: EmailStr
    alert_email: Optional[EmailStr] = None
    team_alert_emails: List[EmailStr] = Field(default_factory=list)


class UserSettingsUpdate(BaseSchema):
    alert_email: Optional[EmailStr] = None
    team_alert_emails: Optional[List[EmailStr]] = None


class IntegrationKeys(BaseSchema):
    vt_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    abuse_api_key: Optional[str] = None




class PcapModelInsights(BaseSchema):
    model_version: Optional[str] = None
    attack_type: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[int] = None
    confidence: Optional[float] = None
    highlight_indicators: List[str] = Field(default_factory=list)
    summary: Optional[str] = None
    learning_signals: Dict[str, Any] = Field(default_factory=dict)


class PcapAnalysisSummary(BaseSchema):
    id: str
    created_at: datetime
    has_alerts: bool
    summary: Dict[str, Any] = Field(default_factory=dict)
    source_file: Optional[str] = None
    blocked_ips: List[str] = Field(default_factory=list)
    malicious_indicators: List[str] = Field(default_factory=list)
    model_insights: Optional[PcapModelInsights] = None
    self_check: Dict[str, bool] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    detections: Dict[str, Any] = Field(default_factory=dict)
    detection_counts: Dict[str, int] = Field(default_factory=dict)
    dns_activity: List[Dict[str, Any]] = Field(default_factory=list)
    tls_summary: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intel_matches: List[Dict[str, Any]] = Field(default_factory=list)
    threat_match_count: int = 0


class PcapAnalysisDetail(PcapAnalysisSummary):
    ips: List[Dict[str, Any]] = Field(default_factory=list)
    alerts: List[Dict[str, Any]] = Field(default_factory=list)


class UserAvatarUpdate(BaseSchema):
    avatar_seed: Optional[str] = None


class ProfileUploadResponse(BaseSchema):
    profile_image_url: str
    message: str


class UserStatusUpdate(BaseSchema):
    status: str


class UserPasswordResetRequest(BaseSchema):
    new_password: Optional[str] = None


class UserPasswordResetResponse(BaseSchema):
    message: str
    new_password: str




class PasswordResetResponse(BaseSchema):
    message: str
    reset_token: str
class PasswordResetConfirmRequest(BaseSchema):
    email: EmailStr
    token: str
    new_password: str = Field(..., min_length=8)


class PasswordResetConfirmResponse(BaseSchema):
    message: str


class LoginResponse(BaseSchema):
    token: str
    user: User
    manager_pending_requests: Optional[int] = None


class UserSignupRequest(BaseSchema):
    email: EmailStr
    role: str = "SOC_ANALYST"


class UserSignupQueued(BaseSchema):
    request_id: str
    status: str = "pending"


class UserRejection(BaseSchema):
    id: str
    status: str
    message: str


class ComputedVerdict(BaseSchema):
    severity: str
    action: str


class IpReputation(BaseSchema):
    ip: str
    vt_summary: str
    abuse_summary: str
    otx_summary: str
    computed_verdict: ComputedVerdict
    rationale: str
    recent_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    related_devices: List[Dict[str, Any]] = Field(default_factory=list)


class SourceIntel(BaseSchema):
    provider: str
    data: Dict[str, Any]


class IpSearchResponse(BaseSchema):
    ip: str
    source_results: Dict[str, SourceIntel]
    aggregated_summary: str
    missing_api_keys: List[str] = Field(default_factory=list)
    computed_verdict: Optional[ComputedVerdict] = None
    verdict_rationale: Optional[str] = None
    blocked: bool = False
    resolved_ips: List[str] = Field(default_factory=list)
    recent_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    related_devices: List[Dict[str, Any]] = Field(default_factory=list)
    malicious_sources: List[str] = Field(default_factory=list)
    intel_summary: Optional[str] = None
    activity_log: List[Dict[str, Any]] = Field(default_factory=list)


class ActivityLog(BaseSchema):
    id: str
    actor: str
    event: str
    metadata: Dict[str, Any]
    created_at: datetime


__all__ = [
    "ActivityLog",
    "Alert",
    "AlertCreate",
    "AlertDetail",
    "AlertStatusUpdate",
    "BlocklistRequest",
    "BlocklistResponse",
    "BlocklistStatusResponse",
    "BlocklistEntry",
    "BlocklistSnapshot",
    "BlocklistListResponse",
    "ComputedVerdict",
    "Device",
    "DeviceCreate",
    "DeviceUpdate",
    "IndicatorSearchResponse",
    "IntegrationKeys",
    "IpReputation",
    "IpSearchResponse",
    "LoginResponse",
    "NanoFileAction",
    "NanoFileResponse",
    "PasswordResetConfirmRequest",
    "PasswordResetConfirmResponse",
    "PasswordResetResponse",
    "PcapAnalysisDetail",
    "PcapModelInsights",
    "PcapAnalysisSummary",
    "PcapUploadResponse",
    "PcapJobStatus",
    "ProfileUploadResponse",
    "Report",
    "ReportDetail",
    "SimulationDevice",
    "SimulationDeviceCreate",
    "SimulationStatePayload",
    "SourceIntel",
    "SystemHealth",
    "TerminalCommandRequest",
    "TerminalCommandResponse",
    "User",
    "UserAvatarUpdate",
    "UserNotificationUpdate",
    "UserPasswordResetRequest",
    "UserPasswordResetResponse",
    "UserPreferences",
    "UserProfileUpdate",
    "UserRejection",
    "UserSettings",
    "UserSettingsUpdate",
    "UserSignupQueued",
    "UserSignupRequest",
    "UserStatusUpdate",
]
