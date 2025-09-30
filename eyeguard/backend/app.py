"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .logging_config import logger, setup_logging
from .routes import alerts, auth, devices, health, reports, search, settings as settings_routes, simulation, pcap, blocklist

setup_logging()
settings = get_settings()
app = FastAPI(title=settings.app_name, version="1.0.0")

static_root = Path(__file__).resolve().parent / "static"
profile_root = static_root / "profile"
profile_root.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_root), name="static")

backend_root = static_root.parent
frontend_build_dir = (backend_root.parent / "frontend" / "dist").resolve()
frontend_index_path = frontend_build_dir / "index.html"
frontend_assets_dir = frontend_build_dir / "assets"
if frontend_assets_dir.is_dir():
    app.mount("/assets", StaticFiles(directory=frontend_assets_dir), name="frontend-assets")

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
app.include_router(blocklist.router)

def frontend_available() -> bool:
    return frontend_index_path.is_file()


@app.get("/", include_in_schema=False)
async def root() -> Response:  # pragma: no cover - simple endpoint
    if frontend_available():
        return FileResponse(frontend_index_path)
    return JSONResponse({"message": "EyeGuard backend is running (simulation mode)."})


@app.get("/{full_path:path}", include_in_schema=False)
async def serve_frontend(full_path: str) -> FileResponse:
    if not frontend_available():
        raise HTTPException(status_code=404)
    if full_path.startswith("api/") or full_path == "api":
        raise HTTPException(status_code=404)
    if full_path in {"docs", "redoc", "openapi.json"}:
        raise HTTPException(status_code=404)
    candidate_path = (frontend_build_dir / full_path).resolve()
    build_root = frontend_build_dir
    index_path = frontend_index_path
    if build_root not in candidate_path.parents and candidate_path != index_path:
        raise HTTPException(status_code=404)
    if candidate_path.is_file():
        return FileResponse(candidate_path)
    return FileResponse(index_path)
