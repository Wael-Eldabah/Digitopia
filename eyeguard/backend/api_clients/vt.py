"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

from typing import Any

from .base import ThreatClient


class VirusTotalClient(ThreatClient):
    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    def _build_url(self, ip: str) -> str:
        return self.base_url.format(ip=ip)

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.api_key or ""}

    async def fetch(self, ip: str) -> dict[str, Any]:
        data = await super().fetch(ip)
        if "data" in data:
            return data
        return {"data": data}
