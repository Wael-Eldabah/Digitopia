"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from fastapi import APIRouter, Query

from ..models.schemas import ThreatForecast
from ..services.forecast import generate_threat_forecast
from ..utils.state import state_store

router = APIRouter(prefix="/api/v1", tags=["predictions"])


@router.get("/predictions/forecast", response_model=ThreatForecast)
async def get_threat_forecast(horizon_hours: int = Query(default=24, ge=6, le=72)) -> ThreatForecast:
    async with state_store._lock:  # type: ignore[attr-defined]
        forecast = generate_threat_forecast(state_store, horizon_hours=horizon_hours)
    return forecast
