"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query

from ..models.schemas import Alert, AlertCreate, AlertDetail, AlertStatusUpdate, User
from ..utils.auth import get_current_user
from ..utils.state import state_store

router = APIRouter(prefix="/api/v1", tags=["alerts"])


def _clone_alert(alert: Alert) -> Alert:
    return Alert(**alert.model_dump())


@router.get("/alerts", response_model=List[Alert])
async def list_alerts(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> list[Alert]:
    async with state_store._lock:  # type: ignore[attr-defined]
        alerts = list(state_store.alerts.values())
        if severity:
            alerts = [alert for alert in alerts if alert.severity == severity]
        if status:
            alerts = [alert for alert in alerts if alert.status == status]
        alerts.sort(key=lambda item: item.detected_at, reverse=True)
        return [_clone_alert(alert) for alert in alerts]


@router.post("/alerts", response_model=Alert, status_code=201)
async def create_alert(payload: AlertCreate, current_user: User = Depends(get_current_user)) -> Alert:
    async with state_store._lock:  # type: ignore[attr-defined]
        alert_id = str(uuid.uuid4())
        alert = Alert(
            id=alert_id,
            detected_at=datetime.utcnow(),
            status="Open",
            action_taken=None,
            **payload.model_dump(),
        )
        state_store.register_alert(alert, actor=current_user.display_name or current_user.email, event="Alert created")
    return _clone_alert(alert)


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: str) -> AlertDetail:
    async with state_store._lock:  # type: ignore[attr-defined]
        alert = state_store.alerts.get(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail={"error_code": "ALERT_NOT_FOUND", "message": "Alert not found"})
        events = state_store.get_alert_history(alert_id)
        return AlertDetail(**alert.model_dump(), events=events)


@router.post("/alerts/{alert_id}/status", response_model=Alert)
async def update_alert_status(
    alert_id: str,
    payload: AlertStatusUpdate,
    current_user: User = Depends(get_current_user),
) -> Alert:
    allowed = {"Open", "Acknowledged", "Resolved"}
    if payload.status not in allowed:
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_STATUS", "message": "Unsupported status"})

    async with state_store._lock:  # type: ignore[attr-defined]
        alert = state_store.alerts.get(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail={"error_code": "ALERT_NOT_FOUND", "message": "Alert not found"})
        updated = Alert(**{**alert.model_dump(), "status": payload.status})
        state_store.alerts[alert_id] = updated
        actor = current_user.display_name or current_user.email
        state_store.append_alert_event(
            alert_id,
            f"Status changed to {payload.status}",
            actor=actor,
            status=updated.status,
            severity=updated.severity,
        )
    return _clone_alert(updated)