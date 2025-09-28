"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from datetime import datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field

from ..models.schemas import (
    LoginResponse,
    PasswordResetConfirmRequest,
    PasswordResetConfirmResponse,
    PasswordResetResponse,
    User,
    UserSignupQueued,
)
from ..utils.auth import get_current_user
from ..utils.state import state_store

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: str = Field(default="SOC_ANALYST", max_length=64)
    display_name: str | None = Field(default=None, max_length=120)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest) -> LoginResponse:
    async with state_store._lock:  # type: ignore[attr-defined]
        user = state_store.authenticate(payload.email, payload.password)
        if not user:
            raise HTTPException(status_code=401, detail={"error_code": "AUTH_FAILED", "message": "Invalid credentials"})
        token = state_store.issue_session_token(user.id)
        pending = len(state_store.pending_users) if user.role == "MANAGER" else None
    return LoginResponse(token=token, user=user, manager_pending_requests=pending)


@router.post("/signup", status_code=202, response_model=UserSignupQueued)
async def signup(payload: SignupRequest) -> UserSignupQueued:
    if not payload.email.lower().endswith("@eyeguard.com"):
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_DOMAIN", "message": "Signup restricted to @eyeguard.com"})

    async with state_store._lock:  # type: ignore[attr-defined]
        if state_store.email_exists(payload.email):
            raise HTTPException(status_code=409, detail={"error_code": "ACCOUNT_EXISTS", "message": "User already active"})
        if state_store.pending_email_exists(payload.email):
            raise HTTPException(status_code=409, detail={"error_code": "REQUEST_EXISTS", "message": "Signup already pending"})

        request_id = str(uuid.uuid4())
        friendly_name = payload.display_name or payload.email.split("@", 1)[0].replace(".", " ").title()
        state_store.pending_users[request_id] = {
            "email": payload.email.lower(),
            "role": payload.role,
            "password_hash": state_store._hash_password(payload.password),  # type: ignore[attr-defined]
            "display_name": friendly_name,
            "requested_at": datetime.utcnow().isoformat(),
        }

    return UserSignupQueued(request_id=request_id, status="pending")


@router.post("/forgot", response_model=PasswordResetResponse)
async def forgot_password(payload: ForgotPasswordRequest) -> PasswordResetResponse:
    async with state_store._lock:  # type: ignore[attr-defined]
        user_id = state_store.find_user_id_by_email(payload.email)
        if not user_id:
            raise HTTPException(status_code=404, detail={"error_code": "NOT_FOUND", "message": "Email not registered"})
        user = state_store.users[user_id]
        reset_token = state_store.issue_password_reset_token(user_id)
    recipients = state_store.collect_user_alert_targets(user)
    if not recipients:
        recipients = [user.email]
    body_lines = [
        f"Hello {user.display_name or user.email},",
        "",
        f"Use the following token to reset your EyeGuard password: {reset_token}.",
        "This token expires when a new one is generated.",
        "",
        "If you did not request a reset, you can safely ignore this message.",
    ]
    body = "\n".join(body_lines)
    state_store.send_email(
        subject="[EyeGuard] Password Reset Token",
        body=body,
        recipients=recipients,
        category="auth.password.reset",
        metadata={"user_id": user.id, "email": user.email},
    )
    state_store.log_activity(user.id, "auth.reset.requested", {"recipients": recipients})
    return PasswordResetResponse(message="Reset instructions sent (simulated)", reset_token=reset_token, sent_to=recipients[0])



@router.post("/reset", response_model=PasswordResetConfirmResponse)
async def confirm_password_reset(payload: PasswordResetConfirmRequest) -> PasswordResetConfirmResponse:
    async with state_store._lock:  # type: ignore[attr-defined]
        user_id = state_store.validate_reset_token(payload.email, payload.token)
        if not user_id:
            raise HTTPException(status_code=400, detail={"error_code": "INVALID_TOKEN", "message": "Invalid or expired reset token"})
        state_store.reset_user_password(user_id, payload.new_password)
        user = state_store.users[user_id]
    state_store.log_activity(user.id, "auth.reset.completed", {"email": user.email})
    return PasswordResetConfirmResponse(message="Password updated. You can now log in.")


@router.get("/me", response_model=User)
async def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user