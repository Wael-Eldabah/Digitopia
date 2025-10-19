"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Set

from ..models.schemas import Alert

SEVERITY_ORDER: Dict[str, int] = {
    "Info": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
}
SEVERITY_BY_RANK: Dict[int, str] = {value: key for key, value in SEVERITY_ORDER.items()}

CORRELATION_THRESHOLD = 4.5
MAX_TIME_GAP_SECONDS = 7200
TOKEN_PATTERN = re.compile(r"[A-Za-z]{4,}")


def severity_rank(value: str | None) -> int:
    normalized = (value or "Low").strip().title()
    return SEVERITY_ORDER.get(normalized, SEVERITY_ORDER["Low"])


def severity_label(rank: int) -> str:
    return SEVERITY_BY_RANK.get(rank, "Low")


def normalize_category(value: str | None) -> str:
    return (value or "").strip().lower()


def _keyword_tokens(text: str | None) -> Set[str]:
    if not text:
        return set()
    return {f"kw:{match.group().lower()}" for match in TOKEN_PATTERN.finditer(text)}


def extract_behavioral_tags(alert: Alert) -> Set[str]:
    tags: Set[str] = set()
    category = normalize_category(alert.category)
    if category:
        tags.add(f"category:{category}")
        tags.update(f"category_token:{token}" for token in category.split())
    severity = normalize_category(alert.severity)
    if severity:
        tags.add(f"severity:{severity}")
    if alert.source_ip:
        tags.add(f"src:{alert.source_ip}")
    if alert.destination_ip:
        tags.add(f"dst:{alert.destination_ip}")
    tags.update(_keyword_tokens(alert.rationale))
    tags.update(_keyword_tokens(alert.intel_summary))
    return tags


def compute_incident_similarity(record: Dict[str, Any], alert: Alert, *, alert_tags: Set[str] | None = None) -> float:
    if not record:
        return 0.0
    last_seen: datetime | None = record.get("last_seen")
    alert_time: datetime | None = getattr(alert, "detected_at", None)
    if not last_seen or not alert_time:
        return 0.0

    tags = alert_tags or extract_behavioral_tags(alert)
    score = 0.0

    time_delta_seconds = abs((alert_time - last_seen).total_seconds())
    if time_delta_seconds <= 300:
        score += 4.0
    elif time_delta_seconds <= 900:
        score += 3.0
    elif time_delta_seconds <= 1800:
        score += 2.0
    elif time_delta_seconds <= 3600:
        score += 1.0
    elif time_delta_seconds <= MAX_TIME_GAP_SECONDS:
        score += 0.25
    else:
        score -= 3.0

    source_ips: Set[str] = record.get("source_ips", set())
    destination_ips: Set[str] = record.get("destination_ips", set())

    if alert.source_ip and alert.source_ip in source_ips:
        score += 4.5
    if alert.destination_ip and alert.destination_ip in destination_ips:
        score += 3.5
    if alert.source_ip and alert.source_ip in destination_ips:
        score += 1.5
    if alert.destination_ip and alert.destination_ip in source_ips:
        score += 1.5

    categories_norm: Set[str] = record.get("categories_norm", set())
    category_norm = normalize_category(alert.category)
    if category_norm in categories_norm:
        score += 2.5
    else:
        category_tokens: Set[str] = record.get("category_tokens", set())
        for token in category_norm.split():
            if token in category_tokens:
                score += 1.0
                break

    behavioral_tags: Set[str] = record.get("behavioral_tags", set())
    shared_tags = len(tags & behavioral_tags)
    if shared_tags:
        score += min(shared_tags * 0.8, 3.2)

    record_severity_rank = record.get("severity_rank", severity_rank("Low"))
    severity_gap = abs(severity_rank(alert.severity) - record_severity_rank)
    if severity_gap == 0:
        score += 0.6
    elif severity_gap == 1:
        score += 0.2
    else:
        score -= min(severity_gap * 0.5, 2.0)

    return score


def derive_incident_status(alerts: Iterable[Alert]) -> str:
    normalized = {str(alert.status or "").strip().lower() for alert in alerts}
    normalized.discard("")
    if not normalized:
        return "Closed"
    if any(status in {"open", "in progress"} for status in normalized):
        return "Active"
    if any(status == "acknowledged" for status in normalized):
        return "Monitoring"
    if all(status == "resolved" for status in normalized):
        return "Contained"
    return "Monitoring"


def highest_severity(alerts: Iterable[Alert]) -> str:
    best_rank = -math.inf
    best_label = "Low"
    for alert in alerts:
        rank = severity_rank(alert.severity)
        if rank > best_rank:
            best_rank = rank
            best_label = (alert.severity or "Low").title()
    return best_label


def build_incident_summary(record: Dict[str, Any], alerts: List[Alert]) -> str:
    if not alerts:
        return "No correlated alerts recorded for this incident yet."

    alert_count = len(alerts)
    source_count = len({alert.source_ip for alert in alerts if alert.source_ip})
    destination_count = len({alert.destination_ip for alert in alerts if alert.destination_ip})
    categories = sorted({alert.category for alert in alerts if alert.category})
    highest = highest_severity(alerts)

    first_seen = min(alert.detected_at for alert in alerts)
    last_seen = max(alert.detected_at for alert in alerts)
    window_seconds = abs((last_seen - first_seen).total_seconds()) if first_seen and last_seen else 0

    if window_seconds < 60:
        timeframe = "within moments"
    elif window_seconds < 3600:
        minutes = max(1, int(window_seconds // 60))
        timeframe = f"within {minutes} minute{'s' if minutes != 1 else ''}"
    else:
        hours = window_seconds / 3600
        timeframe = f"over ~{hours:.1f} hour{'s' if hours >= 1.5 else ''}"

    parts: List[str] = [
        f"{alert_count} alert{'s' if alert_count != 1 else ''}",
    ]
    if source_count:
        parts.append(f"across {source_count} source host{'s' if source_count != 1 else ''}")
    if destination_count:
        parts.append(f"touching {destination_count} destination{'s' if destination_count != 1 else ''}")
    if categories:
        formatted_categories = ", ".join(categories[:3])
        if len(categories) > 3:
            formatted_categories += "…"
        parts.append(f"({formatted_categories})")

    summary = " ".join(parts)
    return f"{summary} observed {timeframe}. Peak severity {highest}."
