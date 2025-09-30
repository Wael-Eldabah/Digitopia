"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from typing import Any, Dict

from .base import ThreatClient


class ShodanClient(ThreatClient):
    """Thin client for Shodan host lookups with mock fallback."""

    name = "shodan"
    base_url = "https://api.shodan.io"

    def _build_url(self, ip: str) -> str:
        base = f"{self.base_url}/shodan/host/{ip}"
        if not self.api_key:
            return base
        return f"{base}?key={self.api_key}"

    def _headers(self) -> Dict[str, str]:
        return {"Accept": "application/json"}

    def load_mock(self, ip: str) -> Dict[str, Any]:
        payload = super().load_mock(ip)
        data = payload.get("data") if isinstance(payload, dict) else None
        if data is None:
            return {"ip": ip, "data": {"ports": [], "tags": [], "vulns": []}}
        if "ports" not in data:
            data.setdefault("ports", [])
        if "tags" not in data:
            data.setdefault("tags", [])
        if "vulns" not in data:
            data.setdefault("vulns", [])
        return payload
