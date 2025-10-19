"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..models.schemas import Incident, IncidentDetail
from ..utils.state import state_store

router = APIRouter(prefix="/api/v1", tags=["incidents"])


@router.get("/incidents", response_model=dict[str, object])
async def list_incidents() -> dict[str, object]:
    async with state_store._lock:  # type: ignore[attr-defined]
        incidents = state_store.list_incidents()
    return {"items": incidents, "total": len(incidents)}


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
async def get_incident(incident_id: str) -> IncidentDetail:
    async with state_store._lock:  # type: ignore[attr-defined]
        incident = state_store.get_incident_detail(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail={"error_code": "INCIDENT_NOT_FOUND", "message": "Incident not found"})
    return incident
