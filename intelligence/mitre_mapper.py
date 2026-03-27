from __future__ import annotations

MITRE_MAP = {
    "BRUTE_FORCE": {"technique": "T1110", "tactic": "Credential Access"},
    "PORT_SCAN": {"technique": "T1046", "tactic": "Discovery"},
    "ANOMALOUS_LOGIN": {"technique": "T1078", "tactic": "Initial Access"},
    "DATA_EXFILTRATION": {"technique": "T1041", "tactic": "Exfiltration"},
    "SQL_INJECTION": {"technique": "T1190", "tactic": "Initial Access"},
    "PHISHING": {"technique": "T1566", "tactic": "Initial Access"},
    "C2_BEACON": {"technique": "T1071", "tactic": "Command and Control"},
    "PRIVILEGE_ESCALATION": {"technique": "T1068", "tactic": "Privilege Escalation"},
    "LATERAL_MOVEMENT": {"technique": "T1021", "tactic": "Lateral Movement"},
}


def map_attack_type(attack_type: str) -> dict:
    return MITRE_MAP.get(attack_type, {"technique": "N/A", "tactic": "None"})
