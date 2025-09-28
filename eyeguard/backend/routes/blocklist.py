"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.schemas import BlocklistRequest, BlocklistResponse, BlocklistStatusResponse, User
from ..services import report_service
from ..services.report_service import DBUnavailable
from ..utils.auth import get_current_user
from ..utils.ip_tools import normalize_ip
from ..utils.state import state_store

router = APIRouter(prefix="/api/blocklist", tags=["blocklist"])


@router.post("", response_model=BlocklistResponse)
async def add_to_blocklist(
    payload: BlocklistRequest,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BlocklistResponse:
    try:
        ip = normalize_ip(payload.ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"ok": False, "error": str(exc)}) from exc
    await report_service.add_blocked_ip(session, ip, current_user.id)
    async with state_store._lock:  # type: ignore[attr-defined]
        state_store.add_blocked_ip(ip, current_user.id)
    try:
        await session.commit()
    except DBUnavailable as exc:  # pragma: no cover - defensive
        logger = report_service.logger  # reuse service logger
        logger.debug("blocklist.commit_fallback", error=str(exc))
    return BlocklistResponse(ok=True)


@router.get("/check", response_model=BlocklistStatusResponse)
async def check_blocklist(
    ip: str = Query(...),
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BlocklistStatusResponse:
    try:
        normalized = normalize_ip(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"ok": False, "error": str(exc)}) from exc
    async with state_store._lock:  # type: ignore[attr-defined]
        in_memory = state_store.is_ip_blocked(normalized)
    if in_memory:
        blocked = True
    else:
        blocked = await report_service.is_ip_blocked(session, normalized)
    return BlocklistStatusResponse(blocked=blocked)
