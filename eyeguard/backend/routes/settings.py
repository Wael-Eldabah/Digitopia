"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import os
import secrets
import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile

from ..models.schemas import (
    ProfileUploadResponse,
    User,
    UserAvatarUpdate,
    UserNotificationUpdate,
    UserPasswordResetRequest,
    UserPasswordResetResponse,
    UserPreferences,
    UserProfileUpdate,
    UserRejection,
    UserSignupQueued,
    UserSignupRequest,
    UserStatusUpdate,
)
from ..utils.auth import get_current_user, require_manager
from ..utils.state import STATIC_PROFILE_ROOT, state_store

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])
ALLOWED_IMAGE_TYPES = {"image/png": ".png", "image/jpeg": ".jpg", "image/jpg": ".jpg", "image/gif": ".gif"}
MAX_IMAGE_BYTES = 2 * 1024 * 1024


def _user_out(user: User) -> User:
    # ensure profile image URL preserved
    return User(**user.model_dump())


@router.get("/profile", response_model=User)
async def get_profile(current_user: User = Depends(get_current_user)) -> User:
    return _user_out(current_user)


@router.get("/users", response_model=List[User])
async def list_users(_: User = Depends(get_current_user)) -> List[User]:
    async with state_store._lock:  # type: ignore[attr-defined]
        return [_user_out(user) for user in state_store.users.values()]


@router.get("/users/pending")
async def list_pending_users(_: User = Depends(require_manager)) -> list[dict[str, str]]:
    async with state_store._lock:  # type: ignore[attr-defined]
        response: list[dict[str, str]] = []
        for request_id, payload in state_store.pending_users.items():
            sanitized = {k: v for k, v in payload.items() if k != "password_hash"}
            sanitized["request_id"] = request_id
            response.append(sanitized)
        return response


@router.get("/users/pending/count")
async def pending_count(_: User = Depends(require_manager)) -> dict[str, int]:
    async with state_store._lock:  # type: ignore[attr-defined]
        return {"pending": len(state_store.pending_users)}


@router.post("/users", response_model=UserSignupQueued, status_code=202)
async def request_signup(payload: UserSignupRequest) -> UserSignupQueued:
    if not payload.email.lower().endswith("@eyeguard.com"):
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_DOMAIN", "message": "Email must end with @eyeguard.com"})
    async with state_store._lock:  # type: ignore[attr-defined]
        if state_store.email_exists(payload.email):
            raise HTTPException(status_code=409, detail={"error_code": "ACCOUNT_EXISTS", "message": "User already active"})
        if state_store.pending_email_exists(payload.email):
            raise HTTPException(status_code=409, detail={"error_code": "REQUEST_EXISTS", "message": "Signup already pending"})
        request_id = str(uuid.uuid4())
        state_store.pending_users[request_id] = {
            "email": payload.email.lower(),
            "role": payload.role,
            "password_hash": state_store._hash_password("changeme123"),  # type: ignore[attr-defined]
            "display_name": payload.email.split("@", 1)[0].replace(".", " ").title(),
            "requested_at": datetime.utcnow().isoformat(),
        }
    return UserSignupQueued(request_id=request_id, status="pending")


@router.patch("/profile", response_model=User)
async def update_profile(
    payload: UserProfileUpdate,
    current_user: User = Depends(get_current_user),
) -> User:
    updates = payload.model_dump(exclude_none=True)
    updates.pop("role", None)
    if not updates:
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_INPUT", "message": "No fields provided"})
    async with state_store._lock:  # type: ignore[attr-defined]
        try:
            updated = state_store.update_user(current_user.id, **updates)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail={"error_code": "CONFLICT", "message": str(exc)}) from exc
    return _user_out(updated)


@router.patch("/profile/notifications", response_model=User)
async def update_notifications(
    payload: UserNotificationUpdate,
    current_user: User = Depends(get_current_user),
) -> User:
    async with state_store._lock:  # type: ignore[attr-defined]
        updated = state_store.set_user_notifications(current_user.id, payload.notifications)
    return _user_out(updated)


@router.post("/profile/avatar", response_model=User)
async def regenerate_avatar(
    _: UserAvatarUpdate | None = None,
    current_user: User = Depends(get_current_user),
) -> User:
    async with state_store._lock:  # type: ignore[attr-defined]
        new_seed = state_store.random_avatar_seed()
        updated = state_store.update_user(current_user.id, avatar_seed=new_seed)
    return _user_out(updated)


@router.post("/profile/avatar/upload", response_model=ProfileUploadResponse)
async def upload_profile_image(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
) -> ProfileUploadResponse:
    if file.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=400, detail={"error": "Unsupported file type"})
    contents = await file.read()
    if len(contents) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=400, detail={"error": "File too large (max 2MB)"})
    extension = ALLOWED_IMAGE_TYPES[file.content_type]
    filename = f"{current_user.id}{extension}"
    output_path = os.path.abspath(os.path.join(STATIC_PROFILE_ROOT, filename))
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as handle:
        handle.write(contents)
    relative_url = f"/static/profile/{filename}?v={int(datetime.utcnow().timestamp())}"
    async with state_store._lock:  # type: ignore[attr-defined]
        state_store.set_profile_image(current_user.id, relative_url)
    state_store.log_activity(current_user.id, "profile.image.upload", {"file": filename})
    return ProfileUploadResponse(profile_image_url=relative_url, message="Profile image updated")


@router.post("/users/{request_id}/approve", response_model=User)
async def approve_signup(request_id: str, actor: User = Depends(require_manager)) -> User:
    async with state_store._lock:  # type: ignore[attr-defined]
        request = state_store.pending_users.pop(request_id, None)
        if not request:
            raise HTTPException(status_code=404, detail={"error_code": "REQUEST_NOT_FOUND", "message": "Signup request not found"})
        user_id = str(uuid.uuid4())
        display_name = request.get("display_name") or request["email"].split("@", 1)[0].replace(".", " ").title()
        user = User(
            id=user_id,
            email=request["email"],
            role=request.get("role", "SOC_ANALYST"),
            status="active",
            display_name=display_name,
            avatar_seed=state_store.random_avatar_seed(),
            profile_image_url=None,
            notifications=UserPreferences(),
        )
        state_store.users[user_id] = user
        password_hash = request.get("password_hash")
        if password_hash:
            state_store.user_credentials[user_id] = password_hash
        state_store.log_activity(actor.id, "user.approved", {"user_id": user_id})
    return _user_out(user)


@router.post("/users/{request_id}/reject", response_model=UserRejection)
async def reject_signup(request_id: str, actor: User = Depends(require_manager)) -> UserRejection:
    async with state_store._lock:  # type: ignore[attr-defined]
        request = state_store.pending_users.pop(request_id, None)
        if not request:
            raise HTTPException(status_code=404, detail={"error_code": "REQUEST_NOT_FOUND", "message": "Signup request not found"})
        state_store.log_activity(actor.id, "user.rejected", {"request_id": request_id})
    return UserRejection(id=request_id, status="rejected", message="Manager rejected signup request")


@router.post("/users/{user_id}/reset-password", response_model=UserPasswordResetResponse)
async def reset_password(
    user_id: str,
    payload: UserPasswordResetRequest,
    actor: User = Depends(require_manager),
) -> UserPasswordResetResponse:
    async with state_store._lock:  # type: ignore[attr-defined]
        if user_id not in state_store.users:
            raise HTTPException(status_code=404, detail={"error": "User not found"})
        if user_id == actor.id:
            raise HTTPException(status_code=400, detail={"error": "Cannot reset your own password"})
        new_password = payload.new_password or secrets.token_hex(4)
        state_store.reset_user_password(user_id, new_password)
        state_store.log_activity(actor.id, "user.password.reset", {"user_id": user_id})
    return UserPasswordResetResponse(message="Password reset", new_password=new_password)


@router.post("/users/{user_id}/status", response_model=User)
async def update_user_status(
    user_id: str,
    payload: UserStatusUpdate,
    actor: User = Depends(require_manager),
) -> User:
    if payload.status not in {"active", "disabled"}:
        raise HTTPException(status_code=400, detail={"error": "Unsupported status"})
    async with state_store._lock:  # type: ignore[attr-defined]
        if user_id not in state_store.users:
            raise HTTPException(status_code=404, detail={"error": "User not found"})
        if user_id == actor.id:
            raise HTTPException(status_code=400, detail={"error": "Cannot change your own status"})
        updated = state_store.set_user_status(user_id, payload.status)
    return _user_out(updated)


@router.delete("/users/{user_id}", status_code=204, response_class=Response)
async def delete_user(user_id: str, actor: User = Depends(require_manager)) -> Response:
    async with state_store._lock:  # type: ignore[attr-defined]
        if user_id not in state_store.users:
            raise HTTPException(status_code=404, detail={"error": "User not found"})
        if user_id == actor.id:
            raise HTTPException(status_code=400, detail={"error": "Cannot delete yourself"})
        state_store.delete_user(user_id)
        state_store.log_activity(actor.id, "user.deleted", {"user_id": user_id})
    return Response(status_code=204)

