"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

from urllib.parse import urlencode

from .base import ThreatClient


class AbuseIPDBClient(ThreatClient):
    name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2/check"

    def _build_url(self, ip: str) -> str:
        return f"{self.base_url}?{urlencode({'ipAddress': ip, 'maxAgeInDays': '90'})}"

    def _headers(self) -> dict[str, str]:
        return {"Key": self.api_key or "", "Accept": "application/json"}
