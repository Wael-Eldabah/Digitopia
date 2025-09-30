
"""Filesystem-backed blocklist store."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

_STORE_PATH = Path(__file__).resolve().parent.parent / "db" / "blocklist.json"


def _ensure_store() -> None:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not _STORE_PATH.exists():
        _STORE_PATH.write_text(json.dumps({"items": []}, indent=2), encoding="utf-8")


def load_entries() -> List[Dict[str, str]]:
    _ensure_store()
    try:
        data = json.loads(_STORE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        data = {"items": []}
    items = data.get("items") or []
    cleaned: List[Dict[str, str]] = []
    for entry in items:
        ip_value = entry.get("ip")
        if not ip_value:
            continue
        blocked_by = entry.get("blocked_by")
        created_at = entry.get("created_at")
        if not isinstance(created_at, str):
            created_at = datetime.utcnow().isoformat()
        cleaned.append({"ip": ip_value, "blocked_by": blocked_by, "created_at": created_at})
    cleaned.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return cleaned


def _write_entries(entries: List[Dict[str, str]]) -> None:
    payload = {"items": entries}
    temp_path = _STORE_PATH.with_suffix(".tmp")
    temp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temp_path, _STORE_PATH)


def add_entry(ip: str, blocked_by: str | None) -> Tuple[bool, List[Dict[str, str]]]:
    entries = load_entries()
    existing = next((entry for entry in entries if entry["ip"] == ip), None)
    if existing:
        if blocked_by and existing.get("blocked_by") != blocked_by:
            existing["blocked_by"] = blocked_by
            _write_entries(entries)
        return False, entries
    created_at = datetime.utcnow().isoformat()
    entries.append({"ip": ip, "blocked_by": blocked_by, "created_at": created_at})
    entries.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    _write_entries(entries)
    return True, entries


def remove_entry(ip: str) -> Tuple[bool, List[Dict[str, str]]]:
    entries = load_entries()
    filtered = [entry for entry in entries if entry.get("ip") != ip]
    if len(filtered) == len(entries):
        return False, entries
    filtered.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    _write_entries(filtered)
    return True, filtered
