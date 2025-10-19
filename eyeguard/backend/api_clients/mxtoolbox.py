"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import asyncio
import base64
from typing import Any, Dict, Optional

import httpx

from ..config import get_settings
from .base import ThreatClientError

settings = get_settings()


class MXToolboxClient:
    """Lightweight wrapper around the MXToolbox header analysis API."""

    def __init__(self, api_key: Optional[str]) -> None:
        self.api_key = api_key or settings.mxtoolbox_api_key
        self.base_url = "https://api.mxtoolbox.com/api/v1"
        self._timeout = settings.request_timeout_seconds
        self._max_retries = settings.request_max_retries

    async def analyze_header(self, raw_email: str) -> Dict[str, Any]:
        """Submit a raw email header to MXToolbox and return the normalized payload."""
        if not self.api_key:
            return self._mock_analysis(
                raw_email,
                reason="MXToolbox API key not configured. Returning heuristic-only results.",
                include_issue=True,
                mode="no-key",
            )
        payload = {"text": raw_email}
        backoff = 0.5
        last_error: Exception | None = None
        for _ in range(self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.post(
                        f"{self.base_url}/lookup/emailheader",
                        headers=self._headers(),
                        json=payload,
                    )
                    response.raise_for_status()
                    data = response.json()
                    return self._normalize_response(data)
            except Exception as exc:  # pragma: no cover - network failure simulated
                last_error = exc
                await asyncio.sleep(backoff)
                backoff *= 2
        if last_error:
            raise ThreatClientError("MXToolbox header analysis failed") from last_error
        raise ThreatClientError("MXToolbox header analysis failed")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": str(self.api_key),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _normalize_response(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Return a predictable payload regardless of MXToolbox response shape."""
        if not isinstance(payload, dict):
            return self._mock_analysis(
                "",
                reason="MXToolbox response malformed. Falling back to heuristics.",
                include_issue=False,
                mode="lookup-error",
            )
        analysis = payload.get("Information") or payload.get("InformationRecords") or []
        issues = payload.get("Issues") or payload.get("Warnings") or []
        result = {
            "status": payload.get("LookupStatus", "unknown"),
            "analysis": analysis,
            "issues": issues,
            "mode": "live",
            "raw": payload,
        }
        return result

    def _mock_analysis(self, raw_email: str, *, reason: str, include_issue: bool, mode: str) -> Dict[str, Any]:
        """Fallback analysis when live MXToolbox lookup is unavailable."""
        encoded_preview = base64.b64encode(raw_email.encode("utf-8", errors="ignore")[:180]).decode("ascii")
        return {
            "status": "mocked",
            "analysis": [
                {"key": "HeaderLength", "value": len(raw_email)},
                {"key": "Preview", "value": encoded_preview},
            ],
            "issues": [reason] if include_issue else [],
            "note": reason if include_issue else None,
            "mode": mode,
            "raw": {},
        }
