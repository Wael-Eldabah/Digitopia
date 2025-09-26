"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

from fastapi import APIRouter

from ..cache import cache_provider
from ..models.schemas import SystemHealth

router = APIRouter(prefix="/api/v1", tags=["health"])


@router.get("/health", response_model=SystemHealth)
async def health() -> SystemHealth:
    cache_status = "connected"
    try:
        cache = await cache_provider.get("__health_check__")
        if cache is None:
            await cache_provider.set("__health_check__", "ok", ex=5)
    except Exception:
        cache_status = "degraded"
    components = {
        "cache": cache_status,
        "database": "simulated",
    }
    return SystemHealth(status="ok", components=components)
