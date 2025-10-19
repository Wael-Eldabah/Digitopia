"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from statistics import mean
from typing import Dict, Iterable, List, Tuple

from ..models.schemas import ForecastRiskPoint, PredictedEntityRisk, ThreatForecast
from ..services.alerting import apply_alert_guidance

SEVERITY_WEIGHTS: Dict[str, int] = {
    "Critical": 6,
    "High": 4,
    "Medium": 2,
    "Low": 1,
    "Info": 1,
}

CONFIDENCE_LEVELS: List[Tuple[float, str]] = [
    (0.7, "High"),
    (0.4, "Medium"),
    (0.0, "Low"),
]


def _severity_weight(value: str | None) -> int:
    if not value:
        return 1
    return SEVERITY_WEIGHTS.get(value.title(), 1)


def _confidence_from_density(sample_count: int, high_ratio: float) -> str:
    if sample_count >= 12 or high_ratio >= 0.55:
        return "High"
    if sample_count >= 6 or high_ratio >= 0.35:
        return "Medium"
    return "Low"


def _bucket_hour(timestamp: datetime) -> datetime:
    return timestamp.replace(minute=0, second=0, microsecond=0)


def _aggregate_alerts(alerts: Iterable) -> Tuple[List, Dict[str, List]]:
    normalized_alerts: List = []
    alerts_by_source: Dict[str, List] = defaultdict(list)
    for alert in alerts:
        enriched = apply_alert_guidance(alert)
        normalized_alerts.append(enriched)
        alerts_by_source[enriched.source_ip].append(enriched)
    return normalized_alerts, alerts_by_source


def generate_threat_forecast(state_store, horizon_hours: int = 24) -> ThreatForecast:
    now = datetime.utcnow()
    window_start = now - timedelta(hours=48)
    alerts = [
        alert
        for alert in state_store.alerts.values()
        if isinstance(alert.detected_at, datetime) and alert.detected_at >= window_start
    ]

    if not alerts:
        baseline_points = [
            ForecastRiskPoint(timestamp=now + timedelta(hours=step * 4), risk_score=15.0 - step, confidence="Low")
            for step in range(max(1, horizon_hours // 4))
        ]
        return ThreatForecast(
            generated_at=now,
            horizon_hours=horizon_hours,
            risk_index=12.0,
            overall_confidence="Low",
            trend_direction="Stable",
            risk_trends=baseline_points,
            high_risk_assets=[],
            high_risk_subnets=[],
        )

    normalized_alerts, alerts_by_source = _aggregate_alerts(alerts)

    hourly_buckets: Dict[datetime, float] = defaultdict(float)
    severity_counts: Counter = Counter()
    for alert in normalized_alerts:
        weight = _severity_weight(alert.severity)
        severity_counts[alert.severity.title()] += 1
        bucket = _bucket_hour(alert.detected_at)
        hourly_buckets[bucket] += weight

    sorted_hours = sorted(hourly_buckets.items())
    hourly_values = [value for _, value in sorted_hours]

    recent_segment = hourly_values[-max(1, len(hourly_values) // 3):]
    historical_segment = hourly_values[:-len(recent_segment)] or hourly_values
    recent_avg = mean(recent_segment) if recent_segment else 0.0
    historical_avg = mean(historical_segment) if historical_segment else 0.0
    trend_delta = recent_avg - historical_avg
    trend_direction = "Increasing" if trend_delta > 1.5 else "Decreasing" if trend_delta < -1.5 else "Stable"

    base_risk_index = min(100.0, recent_avg * 6 if recent_avg else mean(hourly_values) * 5)
    high_severity_total = sum(severity_counts[level] for level in ("Critical", "High"))
    high_ratio = high_severity_total / max(1, len(normalized_alerts))
    overall_confidence = _confidence_from_density(len(normalized_alerts), high_ratio)

    bucket_count = max(3, horizon_hours // 4)
    trend_multiplier = 1.0
    if trend_direction == "Increasing":
        trend_multiplier = 1.15
    elif trend_direction == "Decreasing":
        trend_multiplier = 0.9

    risk_trends: List[ForecastRiskPoint] = []
    current_score = base_risk_index or 10.0
    for step in range(bucket_count):
        step_timestamp = now + timedelta(hours=step * (horizon_hours / bucket_count))
        projected_score = max(5.0, min(100.0, current_score * (trend_multiplier ** (step / max(1, bucket_count - 1)))))
        step_confidence = overall_confidence if step < 2 else ("Medium" if overall_confidence == "High" else "Low")
        risk_trends.append(
            ForecastRiskPoint(
                timestamp=step_timestamp,
                risk_score=round(projected_score, 2),
                confidence=step_confidence,
            )
        )

    asset_predictions: List[PredictedEntityRisk] = []
    subnet_map: Dict[str, List] = defaultdict(list)

    for source_ip, asset_alerts in alerts_by_source.items():
        total_weight = sum(_severity_weight(item.severity) for item in asset_alerts)
        recent_alerts_for_asset = sorted(asset_alerts, key=lambda item: item.detected_at, reverse=True)[:4]
        predicted_vector = Counter(alert.category for alert in asset_alerts if alert.category).most_common(1)
        predicted_vector_value = predicted_vector[0][0] if predicted_vector else "Suspicious Activity"
        high_ratio_asset = sum(1 for entry in asset_alerts if _severity_weight(entry.severity) >= 4) / max(1, len(asset_alerts))
        confidence = _confidence_from_density(len(asset_alerts), high_ratio_asset)
        rationale = (
            f"{len(asset_alerts)} recent alert(s) with {predicted_vector_value.lower()} patterns observed."
        )
        asset_predictions.append(
            PredictedEntityRisk(
                entity=source_ip,
                entity_type="IP",
                risk_score=round(min(100.0, total_weight * (1.2 if confidence == 'High' else 1.0)), 2),
                confidence=confidence,
                predicted_vector=predicted_vector_value,
                supporting_alerts=[alert.id for alert in recent_alerts_for_asset],
                rationale=rationale,
            )
        )

        subnet_prefix = ".".join(source_ip.split(".")[:3]) if source_ip.count(".") >= 3 else source_ip
        subnet_map[subnet_prefix].extend(asset_alerts)

    high_risk_assets = sorted(asset_predictions, key=lambda entry: entry.risk_score, reverse=True)[:5]

    subnet_predictions: List[PredictedEntityRisk] = []
    for subnet, subnet_alerts in subnet_map.items():
        total_weight = sum(_severity_weight(alert.severity) for alert in subnet_alerts)
        categories = Counter(alert.category for alert in subnet_alerts if alert.category)
        predicted_vector_value = categories.most_common(1)[0][0] if categories else "Multi-stage Activity"
        high_ratio_subnet = sum(1 for entry in subnet_alerts if _severity_weight(entry.severity) >= 4) / max(1, len(subnet_alerts))
        confidence = _confidence_from_density(len(subnet_alerts), high_ratio_subnet)
        rationale = (
            f"{len(subnet_alerts)} alert(s) correlated across subnet {subnet}. "
            f"Dominant pattern: {predicted_vector_value.lower()}."
        )
        subnet_predictions.append(
            PredictedEntityRisk(
                entity=f"{subnet}.0/24" if subnet.count(".") == 2 else subnet,
                entity_type="Subnet",
                risk_score=round(min(100.0, total_weight * (1.1 if confidence == 'High' else 0.9)), 2),
                confidence=confidence,
                predicted_vector=predicted_vector_value,
                supporting_alerts=[alert.id for alert in subnet_alerts[:5]],
                rationale=rationale,
            )
        )

    high_risk_subnets = sorted(subnet_predictions, key=lambda entry: entry.risk_score, reverse=True)[:5]

    return ThreatForecast(
        generated_at=now,
        horizon_hours=horizon_hours,
        risk_index=round(base_risk_index, 2),
        overall_confidence=overall_confidence,
        trend_direction=trend_direction,
        risk_trends=risk_trends,
        high_risk_assets=high_risk_assets,
        high_risk_subnets=high_risk_subnets,
    )
