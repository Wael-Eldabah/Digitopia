
"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.schemas import (
    BlocklistEntry,
    BlocklistListResponse,
    BlocklistRequest,
    BlocklistResponse,
    BlocklistSnapshot,
    BlocklistStatusResponse,
    User,
)
from ..services import report_service
from ..services.report_service import DBUnavailable
from ..utils import blocklist_store
from ..utils.auth import get_current_user
from ..utils.ip_tools import normalize_ip
from ..utils.state import state_store


router = APIRouter(prefix="/api/blocklist", tags=["blocklist"])


state_store.sync_blocked_ips(blocklist_store.load_entries())

async def _build_blocklist_snapshot(entries: list[dict[str, Any]] | None = None) -> BlocklistSnapshot:
    if entries is None:
        entries = blocklist_store.load_entries()

    async with state_store._lock:  # type: ignore[attr-defined]
        state_store.sync_blocked_ips(entries)
        updated_at = state_store.blocklist_updated_at or datetime.utcnow()

    detail_objects: list[BlocklistEntry] = []
    for entry in entries:
        ip_value = entry.get("ip")
        if not ip_value:
            continue
        blocked_by = entry.get("blocked_by")
        created_at_raw = entry.get("created_at")
        if isinstance(created_at_raw, datetime):
            created_dt = created_at_raw
        elif isinstance(created_at_raw, str):
            try:
                created_dt = datetime.fromisoformat(created_at_raw)
            except ValueError:
                created_dt = datetime.utcnow()
        else:
            created_dt = datetime.utcnow()
        detail_objects.append(
            BlocklistEntry(
                ip=ip_value,
                blocked_by=str(blocked_by) if blocked_by else 'system',
                created_at=created_dt,
            )
        )

    detail_objects.sort(key=lambda entry: entry.created_at, reverse=True)
    items = [entry.ip for entry in detail_objects]
    snapshot = BlocklistSnapshot(count=len(items), items=items, updated_at=updated_at, details=detail_objects)
    return snapshot


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

    async with state_store._lock:  # type: ignore[attr-defined]
        changed, entries = blocklist_store.add_entry(ip, current_user.id)
        state_store.sync_blocked_ips(entries)

    if changed:
        try:
            await report_service.add_blocked_ip(session, ip, current_user.id)
            await session.commit()
        except DBUnavailable as exc:  # pragma: no cover - degraded path
            report_service.logger.debug("blocklist.persist_fallback", error=str(exc))
            try:
                await session.rollback()
            except Exception:  # pragma: no cover - best effort
                pass
        except Exception as exc:  # pragma: no cover - defensive
            report_service.logger.debug("blocklist.commit_failed", error=str(exc))
            try:
                await session.rollback()
            except Exception:
                pass

    snapshot = await _build_blocklist_snapshot(entries)
    return BlocklistResponse(**snapshot.model_dump())


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

    entries = blocklist_store.load_entries()
    blocked = any(entry.get("ip") == normalized for entry in entries)
    if not blocked:
        try:
            blocked = await report_service.is_ip_blocked(session, normalized)
        except DBUnavailable as exc:  # pragma: no cover - degraded path
            report_service.logger.debug("blocklist.check_fallback", error=str(exc))
            blocked = False
    return BlocklistStatusResponse(blocked=blocked)


@router.get("", response_model=BlocklistListResponse)
async def list_blocklist(
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BlocklistListResponse:
    snapshot = await _build_blocklist_snapshot()
    return BlocklistListResponse(**snapshot.model_dump())


@router.delete("/{ip}", response_model=BlocklistResponse)
async def remove_from_blocklist(
    ip: str,
    session: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BlocklistResponse:
    try:
        normalized = normalize_ip(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"ok": False, "error": str(exc)}) from exc

    async with state_store._lock:  # type: ignore[attr-defined]
        removed, entries = blocklist_store.remove_entry(normalized)
        state_store.sync_blocked_ips(entries)

    if removed:
        try:
            await report_service.remove_blocked_ip(session, normalized)
            await session.commit()
        except DBUnavailable as exc:  # pragma: no cover - degraded path
            report_service.logger.debug("blocklist.remove_persist_fallback", error=str(exc))
            try:
                await session.rollback()
            except Exception:  # pragma: no cover - best effort
                pass
        except Exception as exc:  # pragma: no cover - defensive
            report_service.logger.debug("blocklist.remove_commit_failed", error=str(exc))
            try:
                await session.rollback()
            except Exception:
                pass

    snapshot = await _build_blocklist_snapshot(entries)
    return BlocklistResponse(**snapshot.model_dump())
