"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import asdict, dataclass
from typing import Any, Deque, Dict, List

MODEL_VERSION = "2025.09"


@dataclass
class ModelInsight:
    model_version: str
    attack_type: str
    severity: str
    risk_score: int
    confidence: float
    highlight_indicators: List[str]
    summary: str
    learning_signals: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(self.confidence, 2)
        return payload


class AdaptivePcapModel:
    """Lightweight heuristic model that adapts risk scoring from prior analyses."""

    def __init__(self) -> None:
        self._history: Deque[Dict[str, Any]] = deque(maxlen=100)
        self._attack_counter: Counter[str] = Counter()

    def analyze(self, summary: Dict[str, Any], ip_payloads: List[Dict[str, Any]]) -> ModelInsight:
        features = self._extract_features(summary, ip_payloads)
        risk_score = min(100, features["ti_risk"] + features["dominance"] + features["volume"] + features["exposure"])
        severity = self._severity_for_score(risk_score)
        attack_type = self._classify_attack(features)
        confidence = self._confidence(features, risk_score)
        highlight = features["highlight_indicators"]
        narrative = self._build_summary(attack_type, features, risk_score)
        learning = self._update_learning(risk_score, attack_type, features)
        return ModelInsight(
            model_version=MODEL_VERSION,
            attack_type=attack_type,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            highlight_indicators=highlight,
            summary=narrative,
            learning_signals=learning,
        )

    def _extract_features(self, summary: Dict[str, Any], ip_payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        total_packets = int(summary.get("total_packets") or 0)
        unique_ips = summary.get("unique_ips") or []
        top_ips = summary.get("top_ips") or []
        malicious_entries = [payload for payload in ip_payloads if payload.get("is_malicious")]
        malicious_count = len(malicious_entries)

        dominant_packets = int(top_ips[0].get("packet_count", 0)) if top_ips else 0
        dominance_ratio = (dominant_packets / total_packets * 100) if total_packets else 0.0

        shodan_risks: List[int] = []
        highlighted: List[str] = []
        exposure_contrib = 0
        for payload in ip_payloads:
            shodan_data = (payload.get("source_results") or {}).get("shodan", {}).get("data", {})
            risk = int(shodan_data.get("risk", 0))
            shodan_risks.append(risk)
            if risk >= 60:
                highlighted.append(payload.get("ip"))
                exposure_contrib += 10
            if payload.get("is_malicious"):
                highlighted.append(payload.get("ip"))
        highlighted = list(dict.fromkeys(filter(None, highlighted)))

        max_shodan_risk = max(shodan_risks) if shodan_risks else 0
        ti_high = any((payload.get("severity") or "").lower() in {"high", "critical"} for payload in ip_payloads)

        ti_risk = min(60, malicious_count * 18 + (15 if ti_high else 0) + max_shodan_risk // 2)
        dominance_score = int(min(20, dominance_ratio / 5 * 5))
        volume_score = min(20, total_packets // 500 if total_packets else 0)
        exposure_score = min(30, max_shodan_risk // 2 + exposure_contrib)

        return {
            "total_packets": total_packets,
            "unique_ip_count": len(unique_ips),
            "dominance_ratio": dominance_ratio,
            "dominance": dominance_score,
            "volume": volume_score,
            "exposure": exposure_score,
            "ti_risk": ti_risk,
            "malicious_count": malicious_count,
            "max_shodan_risk": max_shodan_risk,
            "highlight_indicators": highlighted,
        }

    def _severity_for_score(self, score: int) -> str:
        if score >= 85:
            return "Critical"
        if score >= 65:
            return "High"
        if score >= 40:
            return "Medium"
        if score >= 20:
            return "Low"
        return "Info"

    def _classify_attack(self, features: Dict[str, Any]) -> str:
        dominance = features["dominance_ratio"]
        malicious_count = features["malicious_count"]
        max_shodan = features["max_shodan_risk"]
        unique_ips = features["unique_ip_count"]

        if max_shodan >= 80 and dominance >= 40:
            return "Perimeter Breach"
        if dominance >= 75 and malicious_count >= 1:
            return "Beaconing / Exfiltration"
        if unique_ips >= 40 and dominance <= 35:
            return "Port Scan"
        if malicious_count >= 2:
            return "Coordinated Attack"
        return "Suspicious Traffic"

    def _confidence(self, features: Dict[str, Any], risk_score: int) -> float:
        base = 0.35 + (risk_score / 150)
        if features["malicious_count"]:
            base += 0.15
        if features["max_shodan_risk"] >= 70:
            base += 0.1
        return min(0.99, round(base, 3))

    def _build_summary(self, attack_type: str, features: Dict[str, Any], risk_score: int) -> str:
        parts = [
            f"Model classified traffic as {attack_type.lower()}.",
            f"Risk score {risk_score}/100 based on {features['malicious_count']} malicious indicators and {features['unique_ip_count']} unique IPs.",
        ]
        if features["highlight_indicators"]:
            parts.append(f"Key indicators: {', '.join(features['highlight_indicators'][:4])}.")
        if features["max_shodan_risk"]:
            parts.append(f"Maximum Shodan exposure score observed: {features['max_shodan_risk']}.")
        return " ".join(parts)

    def _update_learning(self, risk_score: int, attack_type: str, features: Dict[str, Any]) -> Dict[str, Any]:
        self._history.append({"risk": risk_score, "attack": attack_type})
        self._attack_counter[attack_type] += 1
        avg_risk = sum(item["risk"] for item in self._history) / len(self._history)
        top_attacks = [name for name, _ in self._attack_counter.most_common(3)]
        return {
            "samples_tracked": len(self._history),
            "rolling_average_risk": round(avg_risk, 1),
            "top_attack_types": top_attacks,
            "feature_weights": {
                "ti_risk": features["ti_risk"],
                "dominance": features["dominance"],
                "volume": features["volume"],
                "exposure": features["exposure"],
            },
        }


default_model = AdaptivePcapModel()
adaptive_pcap_model = default_model
