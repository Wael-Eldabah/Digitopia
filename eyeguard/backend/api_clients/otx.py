"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

from .base import ThreatClient


class OTXClient(ThreatClient):
    name = "otx"
    base_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    def _build_url(self, ip: str) -> str:
        return self.base_url.format(ip=ip)

    def _headers(self) -> dict[str, str]:
        return {"X-OTX-API-KEY": self.api_key or ""}
