"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException

from ..models.schemas import User
from .state import state_store


async def get_current_user(token: str = Header(..., alias="X-Eyeguard-Token")) -> User:
    if not token:
        raise HTTPException(status_code=401, detail={"error_code": "AUTH_REQUIRED", "message": "Session token missing"})
    async with state_store._lock:  # type: ignore[attr-defined]
        user = state_store.resolve_session_token(token)
        if not user:
            raise HTTPException(status_code=401, detail={"error_code": "AUTH_INVALID", "message": "Invalid or expired session"})
        return user


async def require_manager(user: User = Depends(get_current_user)) -> User:
    if user.role != "MANAGER":
        raise HTTPException(status_code=403, detail={"error_code": "FORBIDDEN", "message": "Manager privileges required"})
    return user
