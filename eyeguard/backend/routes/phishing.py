"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..models.schemas import EmailPhishingAnalysisRequest, EmailPhishingAnalysisResponse, User
from ..services.phishing_analyzer import analyze_email_message
from ..utils.auth import get_current_user
from ..utils.state import state_store

router = APIRouter(prefix="/api/v1/phishing", tags=["phishing"])


@router.post("/analyze", response_model=EmailPhishingAnalysisResponse)
async def analyze_phishing_email(
    payload: EmailPhishingAnalysisRequest,
    current_user: User = Depends(get_current_user),
) -> EmailPhishingAnalysisResponse:
    del current_user  # not used but enforces authentication
    async with state_store._lock:  # type: ignore[attr-defined]
        integration_keys = state_store.get_integration_keys()
    api_key = integration_keys.get("mxtoolbox_api_key")
    try:
        result = await analyze_email_message(payload, api_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_EMAIL", "message": str(exc)}) from exc
    return result
