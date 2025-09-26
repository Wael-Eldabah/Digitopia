"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx

from ..config import get_settings

MOCK_DATA_FILE = Path(__file__).resolve().parents[2] / "mocks" / "DataExamples.txt"
settings = get_settings()


class ThreatClientError(Exception):
    pass


class ThreatClient:
    name: str
    base_url: str

    def __init__(self, api_key: str | None) -> None:
        self.api_key = api_key
        self._timeout = settings.request_timeout_seconds
        self._max_retries = settings.request_max_retries

    async def fetch(self, ip: str) -> dict[str, Any]:
        if not self.api_key:
            return self.load_mock(ip)
        return await self._call_with_retry(ip)

    async def _call_with_retry(self, ip: str) -> dict[str, Any]:
        backoff = 0.5
        last_error: Exception | None = None
        for _ in range(self._max_retries + 1):
            try:
                return await self._call_api(ip)
            except Exception as exc:
                last_error = exc
                await asyncio.sleep(backoff)
                backoff *= 2
        raise ThreatClientError(f"{self.name} lookup failed") from last_error

    async def _call_api(self, ip: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(self._build_url(ip), headers=self._headers())
            response.raise_for_status()
            return response.json()

    def load_mock(self, ip: str) -> dict[str, Any]:
        return self._load_mock(ip)

    def _build_url(self, ip: str) -> str:  # pragma: no cover - simple glue
        raise NotImplementedError

    def _headers(self) -> dict[str, str]:  # pragma: no cover - simple glue
        raise NotImplementedError

    def _load_mock(self, ip: str) -> dict[str, Any]:
        if not MOCK_DATA_FILE.exists():
            raise ThreatClientError("Mock data file missing")
        with MOCK_DATA_FILE.open("r", encoding="utf-8") as handle:
            records: list[dict[str, Any]] = []
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if data.get("provider") != self.name:
                    continue
                records.append(data)
            if not records:
                raise ThreatClientError(f"No mock data for provider {self.name}")
            for record in records:
                if record.get("ip") == ip:
                    return record
            return records[0]


