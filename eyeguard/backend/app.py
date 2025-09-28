"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .logging_config import logger, setup_logging
from .routes import alerts, auth, devices, health, reports, search, settings as settings_routes, simulation, pcap

setup_logging()
settings = get_settings()
app = FastAPI(title=settings.app_name, version="1.0.0")

static_root = Path(__file__).resolve().parent / "static"
profile_root = static_root / "profile"
profile_root.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_root), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger.info("app.start", mode="simulation")


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:  # pragma: no cover - wiring
    logger.warning("value.error", path=str(request.url), reason=str(exc))
    return JSONResponse(status_code=400, content={"error_code": "VALUE_ERROR", "message": str(exc)})


app.include_router(health.router)
app.include_router(auth.router)
app.include_router(search.router)
app.include_router(search.ip_router)
app.include_router(devices.router)
app.include_router(alerts.router)
app.include_router(reports.router)
app.include_router(pcap.router)
app.include_router(simulation.router)
app.include_router(settings_routes.router)


@app.get("/")
async def root() -> dict[str, str]:  # pragma: no cover - simple endpoint
    return {"message": "EyeGuard backend is running (simulation mode)."}
