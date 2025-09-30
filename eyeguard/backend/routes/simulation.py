"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import asyncio
import hashlib
import os
import random
import uuid
from datetime import datetime
from typing import Dict, List

from fastapi import APIRouter, HTTPException, Response

from ..api_clients.abuse import AbuseIPDBClient
from ..api_clients.base import ThreatClientError
from ..api_clients.otx import OTXClient
from ..api_clients.transformers import transform_abuse, transform_otx, transform_vt
from ..api_clients.vt import VirusTotalClient
from ..config import get_settings
from ..models.schemas import (
    Alert,
    Device,
    NanoFileAction,
    NanoFileResponse,
    SimulationDevice,
    SimulationDeviceCreate,
    TerminalCommandRequest,
    TerminalCommandResponse,
)
from ..utils.ip_tools import normalize_ip
from ..utils.rules import compute_verdict
from ..utils.state import state_store

router = APIRouter(prefix="/api/v1/simulation", tags=["simulation"])
settings = get_settings()
DEFAULT_FILES: Dict[str, str] = {
    "/etc/config.txt": "interface=up\nmtu=1500\nfirewall=enabled\n",
    "/logs/auth.log": "[seed] system boot completed\n",
    "/private/secrets.txt": "token=training-secret\n",
}

VALID_COMMANDS = {"ls", "cd", "nano", "edit", "mv", "rm", "ip"}
DIRECTORY_STRUCTURE = {
    "/": ["etc", "logs", "private"],
    "/etc": ["config.txt", "routes.cfg"],
    "/logs": ["auth.log", "traffic.log"],
    "/private": ["secrets.txt", "backups"],
}


async def _fetch_intel(ip: str) -> tuple[dict, dict, dict]:
    vt_client = VirusTotalClient(settings.vt_api_key)
    otx_client = OTXClient(settings.otx_api_key)
    abuse_client = AbuseIPDBClient(settings.abuse_api_key)

    async def safe_call(client):
        try:
            return await client.fetch(ip)
        except ThreatClientError:
            return client.load_mock(ip)
        except Exception:
            return client.load_mock(ip)

    return await asyncio.gather(
        safe_call(vt_client),
        safe_call(otx_client),
        safe_call(abuse_client),
    )


def _create_device(device_id: str, ip: str, payload: SimulationDeviceCreate) -> Device:
    return Device(
        id=device_id,
        ip_address=ip,
        hostname=payload.hostname,
        device_type=payload.device_type or "Simulated",
        owner_role="SIM_DEVICE",
        traffic_gb=payload.traffic_gb,
        traffic_delta=0.0,
        status="online",
        last_seen_at=datetime.utcnow(),
    )


def _store_alert(alert: Alert, actor: str = "simulation", event: str | None = None) -> None:
    state_store.register_alert(alert, actor=actor, event=event or alert.category)
    state_store.log_activity(actor, "simulation.alert", {"alert_id": alert.id, "category": alert.category})


def _build_alert(device: Device, category: str, severity: str, rationale: str, action: str | None = None) -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        source_ip=device.ip_address,
        destination_ip=None,
        category=category,
        severity=severity,
        status="Open",
        detected_at=datetime.utcnow(),
        action_taken=action,
        rationale=rationale,
    )


def _resolve_path(current: str, target: str) -> str:
    if target.startswith("/"):
        path = target
    elif target == "..":
        path = current.rsplit("/", 1)[0] or "/"
    elif target == ".":
        path = current
    else:
        path = f"{current.rstrip('/')}/{target}" if current != "/" else f"/{target}"
    return path if path else "/"


def _get_session_files(session_id: str) -> Dict[str, str]:
    context = state_store.session_context.setdefault(session_id, {})
    files = context.setdefault("files", DEFAULT_FILES.copy())
    return files


@router.post("/devices", response_model=SimulationDevice, status_code=201)
async def add_simulation_device(payload: SimulationDeviceCreate) -> SimulationDevice:
    normalized_ip = normalize_ip(payload.ip_address)
    async with state_store._lock:  # type: ignore[attr-defined]
        if any(device.ip_address == normalized_ip for device in state_store.devices.values()):
            raise HTTPException(status_code=409, detail={"error_code": "DEVICE_EXISTS", "message": "Device already registered"})
        device_id = str(uuid.uuid4())
        device = _create_device(device_id, normalized_ip, payload)
        state_store.devices[device_id] = device
        session_id = str(uuid.uuid4())
        state_store.sessions[session_id] = SimulationDevice(session_id=session_id, device=device, status_message=None, blocked=False)
        state_store.session_context[session_id] = {
            "cwd": "/",
            "device_id": device_id,
            "traffic_gb": payload.traffic_gb,
            "auto_block": False,
            "blocked": False,
            "status_message": None,
            "files": DEFAULT_FILES.copy(),
        }

    vt_raw, otx_raw, abuse_raw = await _fetch_intel(normalized_ip)
    vt_norm = transform_vt(vt_raw)
    otx_norm = transform_otx(otx_raw)
    abuse_norm = transform_abuse(abuse_raw)
    severity, action, rationale = compute_verdict(vt_norm, otx_norm, abuse_norm)

    triggered_alerts: list[Alert] = []
    status_message: str | None = None
    blocked = False
    async with state_store._lock:  # type: ignore[attr-defined]
        session = state_store.sessions[session_id]
        device = session.device
        actor = f"simulation-session:{session_id}"
        in_blocklist = state_store.is_ip_blocked(normalized_ip)
        if in_blocklist:
            blocked = True
            status_message = "Session blocked: IP is on the blocklist."
            block_alert = _build_alert(device, "Blocklist Enforcement", "High", "Device IP is currently blocklisted.", action="Auto-block")
            _store_alert(block_alert, actor=actor)
            triggered_alerts.append(block_alert)
        if severity in {"High", "Critical"}:
            blocked = True
            verdict_message = rationale or "Threat intelligence identified this IP as malicious."
            if not status_message:
                status_message = f"Threat intel verdict: {verdict_message}"
            alert = _build_alert(device, "Threat Intel Verdict", "High", rationale, action="Auto-block")
            _store_alert(alert, actor=actor)
            triggered_alerts.append(alert)
        elif severity == "Medium":
            alert = _build_alert(device, "Threat Intel Verdict", "Medium", rationale, action="Monitor")
            _store_alert(alert, actor=actor)
            triggered_alerts.append(alert)

        if payload.traffic_gb > 10:
            overload_alert = _build_alert(device, "Traffic Spike", "High", "Device exceeded 10GB traffic threshold.")
            _store_alert(overload_alert, actor=actor)
            triggered_alerts.append(overload_alert)

        if blocked:
            blocked_device = Device(**{**device.model_dump(), "status": "blocked"})
            state_store.devices[device.id] = blocked_device
            device = blocked_device
        state_store.session_context[session_id]["auto_block"] = blocked and not in_blocklist
        state_store.session_context[session_id]["blocked"] = blocked
        state_store.session_context[session_id]["status_message"] = status_message
        state_store.session_context[session_id]["last_alert_ids"] = [alert.id for alert in triggered_alerts]
        state_store.sessions[session_id] = SimulationDevice(
            session_id=session_id,
            device=device,
            status_message=status_message,
            blocked=blocked,
        )

    return state_store.sessions[session_id]


@router.post("/nano", response_model=NanoFileResponse)
async def nano_file_action(request: NanoFileAction) -> NanoFileResponse:
    if request.action not in {"open", "edit", "save"}:
        raise HTTPException(status_code=400, detail={"error": "Unsupported nano action"})
    async with state_store._lock:  # type: ignore[attr-defined]
        context = state_store.session_context.get(request.session_id)
        if not context:
            raise HTTPException(status_code=404, detail={"error": "Simulation session not found"})
        files = _get_session_files(request.session_id)
        file_path = request.file_path
        if file_path not in files:
            return NanoFileResponse(file_path=file_path, error="File not found")
        actor = f"simulation-session:{request.session_id}"
        if request.action == "open":
            state_store.log_activity(actor, "simulation.nano.open", {"file_path": file_path})
            return NanoFileResponse(file_path=file_path, contents=files[file_path], message="File opened")
        if request.contents is None:
            return NanoFileResponse(file_path=file_path, error="Missing contents for write")
        previous_hash = hashlib.sha256(files[file_path].encode()).hexdigest()
        files[file_path] = request.contents
        state_store.file_hashes[file_path] = hashlib.sha256(request.contents.encode()).hexdigest()
        state_store.log_activity(actor, "simulation.nano.save", {"file_path": file_path, "previous_hash": previous_hash})
        action_label = "edited" if request.action == "edit" else "saved"
        return NanoFileResponse(file_path=file_path, contents=files[file_path], message=f"File {action_label}")


@router.delete("/sessions/{session_id}", status_code=204)
async def end_simulation_session(session_id: str) -> Response:
    async with state_store._lock:  # type: ignore[attr-defined]
        session = state_store.sessions.pop(session_id, None)
        context = state_store.session_context.pop(session_id, None)
        if not session:
            raise HTTPException(status_code=404, detail={"error_code": "SESSION_NOT_FOUND", "message": "Simulation session not found"})
        device_id = None
        if context:
            device_id = context.get("device_id")
        if device_id:
            state_store.devices.pop(device_id, None)
        state_store.log_activity(f"simulation-session:{session_id}", "simulation.session.ended", {"device_id": device_id})
    return Response(status_code=204)


@router.post("/terminal", response_model=TerminalCommandResponse)
async def execute_terminal(request: TerminalCommandRequest) -> TerminalCommandResponse:
    command_parts = request.command.strip().split()
    if not command_parts:
        raise HTTPException(status_code=400, detail={"error_code": "EMPTY_COMMAND", "message": "Command is required"})
    command = command_parts[0]
    args = command_parts[1:]
    if command not in VALID_COMMANDS:
        return TerminalCommandResponse(output=f"Command '{command}' not supported.", alerts_triggered=[])

    async with state_store._lock:  # type: ignore[attr-defined]
        session = state_store.sessions.get(request.session_id)
        context = state_store.session_context.get(request.session_id)
        if not session or not context:
            raise HTTPException(status_code=404, detail={"error_code": "SESSION_NOT_FOUND", "message": "Simulation session not found"})
        device = session.device

        alerts: list[Alert] = []
        output = ""
        cwd = context["cwd"]
        files = _get_session_files(request.session_id)
        actor = f"simulation-session:{request.session_id}"

        if command == "ls":
            entries = DIRECTORY_STRUCTURE.get(cwd, [])
            output = "  ".join(entries) if entries else ""
        elif command == "cd":
            target = args[0] if args else "/"
            new_path = _resolve_path(cwd, target)
            if new_path not in DIRECTORY_STRUCTURE:
                output = f"No such directory: {target}"
            else:
                context["cwd"] = new_path
                output = new_path
                if new_path == "/private":
                    alert = _build_alert(device, "Restricted Access", "Medium", "Accessed protected directory /private.")
                    _store_alert(alert, actor=actor)
                    alerts.append(alert)
        elif command in {"nano", "edit"}:
            if not args:
                output = "Specify file to edit"
            else:
                filename = args[0]
                path = _resolve_path(cwd, filename)
                if path not in files:
                    output = "File not found"
                else:
                    old_hash = state_store.file_hashes.get(path, "0")
                    new_contents = f"{random.getrandbits(128):x}"
                    files[path] = new_contents
                    new_hash = hashlib.sha256(new_contents.encode()).hexdigest()
                    state_store.file_hashes[path] = new_hash
                    alert = _build_alert(
                        device,
                        "File Modification",
                        "Medium",
                        f"Edited {path}. Old hash {old_hash[:8]}, new hash {new_hash[:8]}",
                    )
                    _store_alert(alert, actor=actor)
                    alerts.append(alert)
                    output = f"Edited {path}"
        elif command == "mv":
            if len(args) < 2:
                output = "Usage: mv <source> <dest>"
            else:
                src = _resolve_path(cwd, args[0])
                dest = _resolve_path(cwd, args[1])
                files[dest] = files.pop(src, hashlib.sha256(b"mv").hexdigest())
                output = f"Moved {src} to {dest}"
        elif command == "rm":
            if not args:
                output = "Usage: rm <file>"
            else:
                target = _resolve_path(cwd, args[0])
                files.pop(target, None)
                state_store.file_hashes.pop(target, None)
                alert = _build_alert(device, "File Removal", "Low", f"Removed {target}")
                _store_alert(alert, actor=actor)
                alerts.append(alert)
                output = f"Removed {target}"
        elif command == "ip":
            output = f"{device.ip_address}"

    return TerminalCommandResponse(output=output, alerts_triggered=alerts)
