"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import random
import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, HTTPException

from ..models.schemas import Device, DeviceCreate, DeviceUpdate
from ..utils.state import state_store

router = APIRouter(prefix="/api/v1", tags=["devices"])


def _clone_device(device: Device) -> Device:
    return Device(**device.model_dump())


@router.get("/devices", response_model=List[Device])
async def list_devices() -> list[Device]:
    async with state_store._lock:  # type: ignore[attr-defined]
        refreshed: list[Device] = []
        for device_id, device in state_store.devices.items():
            payload = device.model_dump()
            current = payload.get("traffic_gb", 0.0)
            delta = random.uniform(-1.2, 1.2)
            next_value = max(min(current + delta, 24.0), 0.0)
            payload["traffic_gb"] = round(next_value, 2)
            payload["traffic_delta"] = round(next_value - current, 2)
            payload["last_seen_at"] = datetime.utcnow()
            updated = Device(**payload)
            state_store.devices[device_id] = updated
            refreshed.append(_clone_device(updated))
        return refreshed


@router.post("/devices", response_model=Device, status_code=201)
async def create_device(payload: DeviceCreate) -> Device:
    async with state_store._lock:  # type: ignore[attr-defined]
        if any(device.ip_address == payload.ip_address for device in state_store.devices.values()):
            raise HTTPException(status_code=409, detail={"error_code": "DEVICE_EXISTS", "message": "Device with IP already exists"})
        device_id = str(uuid.uuid4())
        base_traffic = payload.traffic_gb or 0.0
        device = Device(
            id=device_id,
            ip_address=payload.ip_address,
            hostname=payload.hostname,
            device_type=payload.device_type,
            owner_role=payload.owner_role,
            traffic_gb=base_traffic,
            traffic_delta=0.0,
            status="online",
            last_seen_at=datetime.utcnow(),
        )
        state_store.devices[device_id] = device
        return _clone_device(device)


@router.get("/devices/{device_id}", response_model=Device)
async def get_device(device_id: str) -> Device:
    async with state_store._lock:  # type: ignore[attr-defined]
        device = state_store.devices.get(device_id)
        if not device:
            raise HTTPException(status_code=404, detail={"error_code": "DEVICE_NOT_FOUND", "message": "Device not found"})
        return _clone_device(device)


@router.patch("/devices/{device_id}", response_model=Device)
async def update_device(device_id: str, payload: DeviceUpdate) -> Device:
    async with state_store._lock:  # type: ignore[attr-defined]
        device = state_store.devices.get(device_id)
        if not device:
            raise HTTPException(status_code=404, detail={"error_code": "DEVICE_NOT_FOUND", "message": "Device not found"})
        update_data = payload.model_dump(exclude_unset=True)
        updated_fields = device.model_dump()
        updated_fields.update({k: v for k, v in update_data.items() if v is not None})
        refreshed = Device(**updated_fields)
        state_store.devices[device_id] = refreshed
        return _clone_device(refreshed)


@router.post("/devices/{device_id}/block", response_model=Device)
async def toggle_block(device_id: str) -> Device:
    async with state_store._lock:  # type: ignore[attr-defined]
        device = state_store.devices.get(device_id)
        if not device:
            raise HTTPException(status_code=404, detail={"error_code": "DEVICE_NOT_FOUND", "message": "Device not found"})
        base = device.model_dump()
        base["status"] = "blocked" if device.status != "blocked" else "online"
        refreshed = Device(**base)
        state_store.devices[device_id] = refreshed
        return _clone_device(refreshed)
