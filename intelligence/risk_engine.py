from __future__ import annotations


def compute_risk_score(
    anomaly_score: float,
    severity_weight: float,
    asset_criticality: float = 0.5,
    time_flag: int = 0,
    ip_reputation_bonus: float = 0.0,
    severity_class: float | None = None,
    time_anomaly_bonus: float | None = None,
) -> dict:
    normalized_severity = float(severity_weight if severity_class is None else severity_class)
    normalized_time_bonus = float(time_flag if time_anomaly_bonus is None else time_anomaly_bonus)

    anomaly_contribution = float(anomaly_score) * 40.0
    severity_contribution = normalized_severity * 25.0
    asset_contribution = float(asset_criticality) * 20.0
    ip_reputation_contribution = float(ip_reputation_bonus) * 10.0
    time_contribution = normalized_time_bonus * 5.0

    risk = (
        anomaly_contribution
        + severity_contribution
        + asset_contribution
        + ip_reputation_contribution
        + time_contribution
    )

    risk = max(0.0, min(100.0, risk))

    if risk <= 39.0:
        band = "LOW"
    elif risk <= 74.0:
        band = "MEDIUM"
    elif risk <= 89.0:
        band = "HIGH"
    else:
        band = "CRITICAL"

    score_breakdown = [
        {"label": "anomaly score", "points": int(round(max(0.0, anomaly_contribution)))},
        {"label": "attack severity", "points": int(round(max(0.0, severity_contribution)))},
        {"label": "critical asset", "points": int(round(max(0.0, asset_contribution)))},
        {"label": "known bad IP", "points": int(round(max(0.0, ip_reputation_contribution)))},
        {"label": "off-hours activity", "points": int(round(max(0.0, time_contribution)))},
    ]
    score_breakdown = [item for item in score_breakdown if int(item["points"]) > 0]
    score_breakdown.sort(key=lambda item: int(item["points"]), reverse=True)

    return {
        "risk_score": int(round(risk)),
        "risk_band": band,
        "score_breakdown": score_breakdown[:3],
    }
