"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from email import message_from_string
from email.message import Message
from email.utils import parseaddr
from typing import Any, Dict, List, Optional, Tuple

from ..api_clients.base import ThreatClientError
from ..api_clients.mxtoolbox import MXToolboxClient
from ..models.schemas import (
    Alert,
    EmailPhishingAnalysisRequest,
    EmailPhishingAnalysisResponse,
    EmailPhishingIndicator,
)
from ..utils.state import state_store

IP_REGEX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
SUSPICIOUS_SUBJECT_KEYWORDS = {"urgent", "payment", "invoice", "password", "suspension", "action required"}


def _safe_domain(value: str) -> str:
    if not value:
        return ""
    return value.split("@", 1)[-1].lower()


def _extract_message(raw_email: str) -> Message:
    return message_from_string(raw_email)


def _scan_headers(message: Message) -> Dict[str, Any]:
    headers: Dict[str, Any] = {}
    for key, value in message.items():
        headers[key.lower()] = value
    return headers


def _parse_authentication_results(value: str | None) -> Dict[str, str]:
    results: Dict[str, str] = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not value:
        return results
    lowered = value.lower()
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}\s*=\s*([a-z0-9_-]+)", lowered)
        if match:
            results[mechanism] = match.group(1)
    return results


def _assess_heuristics(message: Message, headers: Dict[str, Any]) -> Tuple[int, List[EmailPhishingIndicator], Dict[str, Any], List[str]]:
    indicators: List[EmailPhishingIndicator] = []
    suggested_actions: List[str] = []
    score = 10  # base inertia

    from_address = parseaddr(headers.get("from", ""))[1]
    reply_to_address = parseaddr(headers.get("reply-to", ""))[1]
    return_path = headers.get("return-path") or ""
    subject = headers.get("subject", "")
    auth_results = _parse_authentication_results(headers.get("authentication-results"))

    from_domain = _safe_domain(from_address)
    reply_to_domain = _safe_domain(reply_to_address)
    return_path_domain = _safe_domain(return_path.strip("<>"))

    heuristic_data: Dict[str, Any] = {
        "from_address": from_address,
        "reply_to": reply_to_address,
        "return_path": return_path,
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "authentication": auth_results,
    }

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        indicators.append(
            EmailPhishingIndicator(
                type="domain-mismatch",
                value=f"{from_domain} -> {reply_to_domain}",
                score=15,
                description="Reply-To domain differs from visible From address.",
            )
        )
        suggested_actions.append("Verify sender authenticity before responding.")
        score += 15

    if return_path_domain and from_domain and return_path_domain != from_domain:
        indicators.append(
            EmailPhishingIndicator(
                type="envelope-mismatch",
                value=f"{from_domain} vs {return_path_domain}",
                score=10,
                description="Return-Path domain deviates from visible sender.",
            )
        )
        score += 10

    for mechanism, outcome in auth_results.items():
        if outcome in {"fail", "softfail", "temperror"}:
            indicators.append(
                EmailPhishingIndicator(
                    type="auth-failure",
                    value=f"{mechanism}:{outcome}",
                    score=15,
                    description=f"{mechanism.upper()} authentication did not pass.",
                )
            )
            suggested_actions.append(f"Record {mechanism.upper()} failure for follow-up.")
            score += 18
        elif outcome == "pass":
            score -= 5

    received_headers = message.get_all("received", [])
    received_count = len(received_headers)
    heuristic_data["received_count"] = received_count

    if received_count <= 1:
        indicators.append(
            EmailPhishingIndicator(
                type="received-chain",
                value=str(received_count),
                score=5,
                description="Unusually short Received chain detected.",
            )
        )
        score += 5

    suspicious_ips: List[str] = []
    for header in received_headers[:4]:
        suspicious_ips.extend(IP_REGEX.findall(header))
    if suspicious_ips:
        unique_ips = sorted(set(suspicious_ips))
        indicators.append(
            EmailPhishingIndicator(
                type="relay-ip",
                value=", ".join(unique_ips[:5]),
                score=8,
                description="IP addresses extracted from Received headers.",
            )
        )
        heuristic_data["relay_ips"] = unique_ips

    if subject:
        tokens = {token.strip("!?.").lower() for token in subject.split()}
        matched = sorted(SUSPICIOUS_SUBJECT_KEYWORDS & tokens)
        if matched:
            indicators.append(
                EmailPhishingIndicator(
                    type="subject-keyword",
                    value=", ".join(matched),
                    score=10,
                    description="Subject contains high-risk phishing keywords.",
                )
            )
            suggested_actions.append("Escalate to phishing playbook due to subject lures.")
            score += 12

    has_attachments = any(part.get_content_disposition() == "attachment" for part in message.walk())
    heuristic_data["has_attachments"] = has_attachments
    if has_attachments:
        indicators.append(
            EmailPhishingIndicator(
                type="attachment",
                value="present",
                score=12,
                description="Email includes attachment(s); review for malicious payloads.",
            )
        )
        suggested_actions.append("Scan attachments with malware sandbox.")
        score += 12

    score = max(0, min(100, score))
    return score, indicators, heuristic_data, suggested_actions


async def analyze_email_message(request: EmailPhishingAnalysisRequest, stored_api_key: Optional[str]) -> EmailPhishingAnalysisResponse:
    raw_email = (request.raw_email or "").strip()
    if not raw_email:
        raise ValueError("raw_email cannot be empty")

    message = _extract_message(raw_email)
    headers = _scan_headers(message)
    heuristic_score, heuristic_indicators, heuristic_data, suggested_actions = _assess_heuristics(message, headers)

    effective_api_key = (stored_api_key or "").strip()
    client = MXToolboxClient(effective_api_key or None)
    try:
        mx_results = await client.analyze_header(raw_email)
    except ThreatClientError:
        mx_results = client._mock_analysis(  # type: ignore[attr-defined]
            raw_email,
            reason="MXToolbox lookup failed. Returning heuristic-only results.",
            include_issue=False,
            mode="lookup-error",
        )

    mx_penalty = 0
    mx_issues = mx_results.get("issues") or []
    if isinstance(mx_issues, list):
        mx_penalty = min(25, len(mx_issues) * 5)
    total_score = max(0, min(100, heuristic_score + mx_penalty))

    display_mx_results = None if mx_results.get("mode") == "lookup-error" else mx_results

    if total_score >= 70:
        risk_level = "High"
    elif total_score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    summary_bits: List[str] = []
    if risk_level == "High":
        summary_bits.append("Likely phishing attempt detected.")
    elif risk_level == "Medium":
        summary_bits.append("Suspicious email characteristics observed.")
    else:
        summary_bits.append("Minimal phishing indicators detected.")
    if mx_issues:
        summary_bits.append(f"MXToolbox highlighted {len(mx_issues)} issue(s).")
    if any(ind.type == "auth-failure" for ind in heuristic_indicators):
        summary_bits.append("Authentication failures present.")

    response = EmailPhishingAnalysisResponse(
        risk_score=total_score,
        risk_level=risk_level,
        summary=" ".join(summary_bits),
        indicators=heuristic_indicators,
        heuristics=heuristic_data,
        mx_findings=display_mx_results,
        suggested_actions=suggested_actions or ["Monitor user reports for similar messages."],
        alerts_created=[],
    )

    if request.create_alert and total_score >= 40:
        severity = "High" if total_score >= 70 else "Medium"
        rationale = response.summary
        actor = "phishing-analyzer"
        relay_ips = heuristic_data.get("relay_ips") or []
        source_hint = relay_ips[0] if relay_ips else heuristic_data.get("from_domain") or "email"
        alert = Alert(
            id=str(uuid.uuid4()),
            detected_at=datetime.utcnow(),
            source_ip=source_hint,
            destination_ip=None,
            category="Phishing Email Analysis",
            severity=severity,
            status="Open",
            rationale=rationale,
            playbook="Investigate suspected phishing email",
        )
        async with state_store._lock:  # type: ignore[attr-defined]
            registered = state_store.register_alert(alert, actor=actor, event=request.label or "Phishing email analyzed")
        response.alerts_created.append(registered.id)

    return response
