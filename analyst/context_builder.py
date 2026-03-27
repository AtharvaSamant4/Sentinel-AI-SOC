from __future__ import annotations

import re
from typing import Any


def build_context(threat: dict[str, Any]) -> dict[str, Any]:
    attack_type = str(threat.get("attack_type", "UNKNOWN"))
    summary = _summary_from_attack_type(attack_type)

    details = {
        "source_ip": threat.get("source_ip", "unknown"),
        "destination_ip": threat.get("destination_ip", "unknown"),
        "destination_port": threat.get("destination_port", "unknown"),
        "risk_score": threat.get("risk_score", 0),
        "severity": threat.get("severity", "LOW"),
        "anomaly_score": threat.get("anomaly_score", 0.0),
        "mitre": _mitre_label(threat.get("mitre", {})),
        "reason": threat.get("reason", "No additional details"),
        "threat_actor": threat.get("threat_actor"),
        "ip_reputation": threat.get("ip_reputation"),
        "ip_intel": threat.get("ip_intel"),
        "kill_chain": threat.get("kill_chain"),
    }

    failed_attempts = _extract_first_int(str(threat.get("reason", "")))
    if failed_attempts is not None:
        details["failed_attempts"] = failed_attempts

    live_context = threat.get("live_context", {})
    return {"summary": summary, "details": details, "live_context": live_context}


def build_prompt(context: dict[str, Any]) -> str:
    details = context.get("details", {})
    live_context = context.get("live_context", {})
    failed_attempts = details.get("failed_attempts", "unknown")
    event_count = live_context.get("event_count", "unknown")
    active_threats = live_context.get("active_threats", "unknown")
    geo_data = live_context.get("geo_data", {})
    persistent_threats = live_context.get("persistent_threats", [])
    if isinstance(persistent_threats, list) and persistent_threats:
        persistent_text = ", ".join(
            [
                f"{item.get('source_ip', 'unknown')} ({item.get('duration', 'unknown')})"
                for item in persistent_threats
                if isinstance(item, dict)
            ]
        )
        if not persistent_text:
            persistent_text = "none"
    else:
        persistent_text = "none"
    actor = details.get("threat_actor") if isinstance(details.get("threat_actor"), dict) else None
    actor_name = str(actor.get("name", "Unknown")) if actor else "Unknown"
    actor_aka = str(actor.get("aka", "Unknown")) if actor else "Unknown"
    actor_description = str(actor.get("description", "No matched actor profile.")) if actor else "No matched actor profile."
    actor_origin = str(actor.get("origin", "Unknown")) if actor else "Unknown"
    actor_confidence = actor.get("confidence", 0) if actor else 0
    ip_reputation = details.get("ip_reputation") if isinstance(details.get("ip_reputation"), dict) else None
    rep_score = int(ip_reputation.get("abuseConfidenceScore", 0)) if ip_reputation else 0
    rep_reports = int(ip_reputation.get("totalReports", 0)) if ip_reputation else 0
    rep_last_seen = str(ip_reputation.get("lastReportedAt", "unknown")) if ip_reputation else "unknown"
    rep_country = str(ip_reputation.get("countryCode", "XX")) if ip_reputation else "XX"
    rep_whitelist = bool(ip_reputation.get("isWhitelisted", False)) if ip_reputation else False
    ip_intel = details.get("ip_intel") if isinstance(details.get("ip_intel"), dict) else None
    intel_score = int(ip_intel.get("abuse_score", 0)) if ip_intel else 0
    intel_reports = int(ip_intel.get("total_reports", 0)) if ip_intel else 0
    kill_chain = details.get("kill_chain") if isinstance(details.get("kill_chain"), dict) else None
    kill_chain_active = kill_chain.get("active_stage_names", []) if kill_chain else []
    kill_chain_active_text = ", ".join([str(stage) for stage in kill_chain_active]) if kill_chain_active else "none"
    kill_chain_campaign_active = bool(kill_chain.get("campaign_active", False)) if kill_chain else False
    campaign_prompt = ""
    if kill_chain_campaign_active and len(kill_chain_active) >= 3:
        campaign_prompt = (
            "Campaign inference request: "
            f"The kill chain shows {kill_chain_active_text} are all active. "
            "What does this tell us about where the attacker is in their campaign "
            "and what is their likely next move?\n\n"
        )

    return (
        "You are a senior cybersecurity analyst in a Security Operations Center.\n\n"
        "Output policy: plain text only. Do not use markdown symbols such as *, **, #, or ``` in your response.\n"
        "Ground every statement in the provided evidence. If uncertain, explicitly say 'Unknown from available telemetry'.\n\n"
        "Analyze the following threat:\n"
        f"- Attack Type: {context.get('summary', 'Unknown threat')}\n"
        f"- Risk Score: {details.get('risk_score', 0)}/100\n"
        f"- Severity: {details.get('severity', 'LOW')}\n"
        f"- MITRE: {details.get('mitre', 'N/A')}\n"
        "- Event Details:\n"
        f"  - Source IP: {details.get('source_ip', 'unknown')}\n"
        f"  - Destination IP: {details.get('destination_ip', 'unknown')}\n"
        f"  - Destination Port: {details.get('destination_port', 'unknown')}\n"
        f"  - Anomaly Score: {details.get('anomaly_score', 0.0)}\n"
        f"  - Failed Attempts (if login-related): {failed_attempts}\n"
        f"  - Detection Reason: {details.get('reason', 'N/A')}\n\n"
        "Live SOC context:\n"
        f"- Event Count: {event_count}\n"
        f"- Active Threats: {active_threats}\n"
        f"- Geo Data: {geo_data}\n"
        f"- Persistent threats: {persistent_text}\n\n"
        "Threat actor fingerprint context:\n"
        f"- Matched threat actor: {actor_name} ({actor_aka}) - {actor_description}\n"
        f"- Likely Actor: {actor_name}\n"
        f"- Origin: {actor_origin}\n"
        f"- Match Confidence Signals: {actor_confidence}\n"
        f"- Actor Profile: {actor_description}\n\n"
        "IP reputation context (AbuseIPDB):\n"
        f"- IP reputation: abuse score {intel_score}/100, reported by {intel_reports} organizations globally\n"
        f"- Confidence Score: {rep_score}%\n"
        f"- Total Reports: {rep_reports}\n"
        f"- Last Reported At: {rep_last_seen}\n"
        f"- Country Code: {rep_country}\n"
        f"- Whitelisted: {rep_whitelist}\n\n"
        "Kill chain campaign context:\n"
        f"- Active Stages: {kill_chain_active_text}\n"
        f"- Campaign Active: {kill_chain_campaign_active}\n\n"
        f"{campaign_prompt}"
        "Explain clearly and concisely:\n"
        "1. What is happening\n"
        "2. Why this is dangerous\n"
        "3. What attacker is likely doing\n"
        "4. Immediate mitigation steps\n\n"
        "Keep the answer professional, actionable, and under 120 words."
    )


def build_auto_analysis_message(threat: dict[str, Any]) -> str:
    threat_type = str(threat.get("attack_type", "UNKNOWN"))
    source_ip = str(threat.get("source_ip", "unknown"))
    score = int(float(threat.get("risk_score", 0) or 0))
    mitre = threat.get("mitre", {}) if isinstance(threat.get("mitre", {}), dict) else {}
    mitre_id = str(mitre.get("technique", "N/A"))

    return (
        f"A {threat_type} was just detected from IP {source_ip} with risk score {score}/100. "
        f"MITRE technique: {mitre_id}. Analyze this threat, explain what the attacker is trying to do "
        "in plain English, rate danger 1-10, and give 3 immediate action steps. "
        "Output plain text only with no markdown symbols."
    )


def _summary_from_attack_type(attack_type: str) -> str:
    mapping = {
        "BRUTE_FORCE": "Brute force attack detected",
        "PORT_SCAN": "Port scanning activity detected",
        "ANOMALOUS_LOGIN": "Anomalous login behavior detected",
        "DATA_EXFILTRATION": "Potential data exfiltration detected",
        "SQL_INJECTION": "SQL injection attempt detected",
        "PHISHING": "Phishing attack detected",
        "C2_BEACON": "Command-and-control beacon detected",
        "LATERAL_MOVEMENT": "Lateral movement detected",
        "PRIVILEGE_ESCALATION": "Privilege escalation detected",
        "NORMAL": "No malicious activity identified",
    }
    return mapping.get(attack_type, f"{attack_type} detected")


def _mitre_label(mitre: Any) -> str:
    if not isinstance(mitre, dict):
        return "N/A"
    technique = mitre.get("technique", "N/A")
    tactic = mitre.get("tactic", "None")
    return f"{technique} ({tactic})"


def _extract_first_int(text: str) -> int | None:
    match = re.search(r"\b(\d+)\b", text)
    if not match:
        return None
    return int(match.group(1))
