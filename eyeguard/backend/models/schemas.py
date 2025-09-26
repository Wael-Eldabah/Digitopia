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
    rationale: Optional[str] = None
    action_taken: Optional[str] = None


class AlertCreate(BaseSchema):
    source_ip: str
    destination_ip: Optional[str] = None
    category: str
    severity: str
    rationale: Optional[str] = None


class AlertStatusUpdate(BaseSchema):
    status: str


class AlertDetail(Alert):
    events: List[Dict[str, Any]] = Field(default_factory=list)


class Report(BaseSchema):\n    id: str\n    type: str\n    title: str\n    has_alerts: bool\n    created_at: datetime\n    summary: Dict[str, Any] = Field(default_factory=dict)\n    cached: Optional[bool] = None\n\n\nclass ReportDetail(Report):\n    payload: Dict[str, Any] = Field(default_factory=dict)\n

class SimulationDeviceCreate(BaseSchema):
    ip_address: str
    hostname: str
    traffic_gb: float
    device_type: Optional[str] = None


class SimulationDevice(BaseSchema):\n    session_id: str\n    device: Device\n    status_message: Optional[str] = None\n    blocked: bool = False\n

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
    profile_image_url: Optional[str] = None\n    alert_email: Optional[EmailStr] = None\n    team_alert_emails: List[EmailStr] = Field(default_factory=list)\n    notifications: UserPreferences = Field(default_factory=UserPreferences)\n

class UserProfileUpdate(BaseSchema):\n    display_name: Optional[str] = None\n    email: Optional[EmailStr] = None\n    alert_email: Optional[EmailStr] = None\n    team_alert_emails: Optional[List[EmailStr]] = None\n

class UserNotificationUpdate(BaseSchema):
    notifications: UserPreferences


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


class PasswordResetResponse(BaseSchema):
    message: str
    reset_token: str


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
    "ComputedVerdict",
    "Device",
    "DeviceCreate",
    "DeviceUpdate",
    "IpReputation",
    "IpSearchResponse",
    "LoginResponse",
    "NanoFileAction",
    "NanoFileResponse",
    "PasswordResetResponse",
    "ProfileUploadResponse",
    "Report",
    "ReportDetail",
    "SimulationDevice",
    "SimulationDeviceCreate",
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
    "UserSignupQueued",
    "UserSignupRequest",
    "UserStatusUpdate",
]

