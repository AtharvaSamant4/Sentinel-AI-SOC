from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
import random
from typing import AsyncIterator

from nlp.service import classify_email


DEFAULT_COUNTRY_POOL = ["DE", "NL"]


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _interval_bounds() -> tuple[float, float]:
    default_min = 2.0
    default_max = 3.0
    raw_min = os.getenv("SENTINEL_EVENT_MIN_INTERVAL_SECONDS", str(default_min))
    raw_max = os.getenv("SENTINEL_EVENT_MAX_INTERVAL_SECONDS", str(default_max))

    try:
        min_interval = float(raw_min)
    except ValueError:
        min_interval = default_min

    try:
        max_interval = float(raw_max)
    except ValueError:
        max_interval = default_max

    min_interval = max(0.1, min_interval)
    max_interval = max(min_interval, max_interval)
    return (min_interval, max_interval)


def _stable_country_for_ip(source_ip: str) -> str:
    ip = str(source_ip or "").strip()
    if not ip:
        return random.choice(DEFAULT_COUNTRY_POOL)

    if ip.startswith("185.220."):
        return "RU"
    if ip.startswith("91.108."):
        return "CN"
    if ip.startswith("103.21."):
        return "IR"
    if ip.startswith("198.51."):
        return "KP"
    if ip.startswith("45.33."):
        return "BR"

    # Deterministic default for all other prefixes.
    parts = ip.split(".")
    last = 0
    if parts:
        try:
            last = int(parts[-1])
        except ValueError:
            last = sum(ord(ch) for ch in parts[-1])
    return DEFAULT_COUNTRY_POOL[last % len(DEFAULT_COUNTRY_POOL)]


async def brute_force_attack(
    duration_seconds: int = 20,
    source_ip: str | None = None,
    target_ip: str | None = None,
) -> AsyncIterator[dict]:
    source_ip = source_ip or _ip()
    target_ip = target_ip or _ip()
    username = random.choice(["admin", "root", "finance", "ops", "support"])
    country = _stable_country_for_ip(source_ip)
    min_interval, max_interval = _interval_bounds()
    interval = random.uniform(min_interval, max_interval)
    attempts = max(1, int(duration_seconds / interval))

    for _ in range(attempts):
        yield {
            "timestamp": _ts(),
            "source_ip": source_ip,
            "destination_ip": target_ip,
            "destination_port": 22,
            "protocol": "SSH",
            "event_type": "login",
            "username": username,
            "status": "failure",
            "bytes_transferred": random.randint(60, 400),
            "country": country,
            "is_attack": True,
        }
        await asyncio.sleep(interval)


async def port_scan_attack(
    duration_seconds: int = 15,
    source_ip: str | None = None,
    target_ip: str | None = None,
) -> AsyncIterator[dict]:
    source_ip = source_ip or _ip()
    target_ip = target_ip or _ip()
    country = _stable_country_for_ip(source_ip)
    min_interval, max_interval = _interval_bounds()
    interval = random.uniform(min_interval, max_interval)
    attempts = max(1, int(duration_seconds / interval))
    attempts = min(attempts, 200)
    ports = random.sample(range(1, 65535), attempts)

    for port in ports:
        yield {
            "timestamp": _ts(),
            "source_ip": source_ip,
            "destination_ip": target_ip,
            "destination_port": port,
            "protocol": random.choice(["TCP", "UDP"]),
            "event_type": "connection",
            "username": None,
            "status": "failure",
            "bytes_transferred": random.randint(40, 250),
            "country": country,
            "is_attack": True,
        }
        await asyncio.sleep(interval)


_PHISHING_SUBJECTS = [
    "Urgent: Your account has been suspended",
    "Action required: Verify your credentials immediately",
    "Security alert: Unusual login detected on your account",
    "Final notice: Update your payment information now",
    "Your account will be closed — act now",
]

_PHISHING_BODIES = [
    "Dear customer, your account has been locked due to suspicious activity. "
    "Click here to verify your identity and restore access immediately.",
    "We detected an unauthorized login attempt. Confirm your password reset now "
    "or your account will be permanently suspended within 24 hours.",
    "Urgent: Your bank account requires immediate verification. "
    "Failure to act now will result in account termination. Click the link below.",
]


_SQLI_PAYLOADS = [
    "' OR '1'='1' --",
    "' UNION SELECT username, password FROM users --",
    "'; DROP TABLE sessions; --",
    "' OR 1=1 UNION SELECT null, table_name FROM information_schema.tables --",
    "admin'--",
    "' OR 'x'='x",
    "1; SELECT * FROM users WHERE '1'='1",
]

_SQLI_PATHS = [
    "/login",
    "/search",
    "/api/user",
    "/admin/query",
    "/products",
]


async def sql_injection_attack(
    duration_seconds: int = 18,
    source_ip: str | None = None,
    target_ip: str | None = None,
) -> AsyncIterator[dict]:
    source_ip = source_ip or _ip()
    target_ip = target_ip or _ip()
    country = _stable_country_for_ip(source_ip)
    min_interval, max_interval = _interval_bounds()
    interval = random.uniform(min_interval, max_interval)
    attempts = max(1, int(duration_seconds / interval))

    for _ in range(attempts):
        payload = random.choice(_SQLI_PAYLOADS)
        path = random.choice(_SQLI_PATHS)
        yield {
            "timestamp": _ts(),
            "source_ip": source_ip,
            "destination_ip": target_ip,
            "destination_port": 443,
            "protocol": "HTTP",
            "event_type": "request",
            "username": None,
            "status": random.choice(["failure", "failure", "success"]),
            "bytes_transferred": random.randint(800, 4000),
            "country": country,
            "is_attack": True,
            "payload": f"GET {path}?id={payload}",
            "user_agent": "sqlmap/1.7.8",
        }
        await asyncio.sleep(interval)


async def c2_beacon_attack(
    duration_seconds: int = 24,
    source_ip: str | None = None,
    target_ip: str | None = None,
) -> AsyncIterator[dict]:
    source_ip = source_ip or _ip()
    target_ip = target_ip or _ip()
    country = _stable_country_for_ip(source_ip)
    beacon_interval = random.choice([30, 45, 60])
    min_interval, max_interval = _interval_bounds()
    interval = random.uniform(min_interval, max_interval)
    attempts = max(1, int(duration_seconds / interval))

    for _ in range(attempts):
        yield {
            "timestamp": _ts(),
            "source_ip": source_ip,
            "destination_ip": target_ip,
            "destination_port": random.choice([443, 8443, 80, 4444]),
            "protocol": "TCP",
            "event_type": "connection",
            "username": None,
            "status": "success",
            "bytes_transferred": random.randint(200, 800),
            "country": country,
            "is_attack": True,
            "c2_signal": True,
            "beacon_interval_seconds": beacon_interval,
            "payload": f"C2 beacon @ {beacon_interval}s interval",
        }
        await asyncio.sleep(interval)


async def phishing_attack(
    duration_seconds: int = 5,
    source_ip: str | None = None,
    target_ip: str | None = None,
) -> AsyncIterator[dict]:
    source_ip = source_ip or _ip()
    target_ip = target_ip or _ip()
    country = _stable_country_for_ip(source_ip)
    username = random.choice(["finance", "ceo", "hr", "it-admin", "accounts"])

    subject = random.choice(_PHISHING_SUBJECTS)
    body = random.choice(_PHISHING_BODIES)
    payload_text = f"{subject} {body}"

    # Real NLP classification — run in thread so we don't block the event loop.
    nlp_result = await asyncio.to_thread(classify_email, subject, body)
    phishing_confidence = nlp_result["confidence"]
    phishing_signal = nlp_result["is_phishing"]

    await asyncio.sleep(duration_seconds)
    yield {
        "timestamp": _ts(),
        "source_ip": source_ip,
        "destination_ip": target_ip,
        "destination_port": 443,
        "protocol": "HTTP",
        "event_type": "request",
        "username": username,
        "status": "failure",
        "bytes_transferred": random.randint(70000, 120000),
        "country": country,
        "is_attack": True,
        "phishing_signal": phishing_signal,
        "phishing_confidence": phishing_confidence,
        "phishing_nlp_method": nlp_result["method"],
        "phishing_risk": "HIGH" if phishing_confidence >= 0.7 else "MEDIUM",
        "payload": payload_text,
    }


# ---------------------------------------------------------------------------
# Full breach scenario — attacker wins, shows the complete kill chain
# ---------------------------------------------------------------------------

_BREACH_STAGES = [
    ("RECONNAISSANCE",      "PORT_SCAN",         "Attacker scanning for open ports and services"),
    ("INITIAL_ACCESS",      "BRUTE_FORCE",        "Brute-forcing SSH credentials"),
    ("PERSISTENCE",         "C2_BEACON",          "Dropping backdoor and establishing C2 channel"),
    ("PRIVILEGE_ESCALATION","PRIVILEGE_ESCALATION","Exploiting sudo misconfiguration for root"),
    ("LATERAL_MOVEMENT",    "LATERAL_MOVEMENT",   "Moving from DMZ host to internal network"),
    ("EXFILTRATION",        "DATA_EXFILTRATION",  "Exfiltrating database dump over HTTPS"),
    ("IMPACT",              "DATA_EXFILTRATION",  "Ransomware deployed — files encrypted"),
]

_BREACH_PORTS = {
    "RECONNAISSANCE":       [22, 80, 443, 3389, 8080],
    "INITIAL_ACCESS":       [22],
    "PERSISTENCE":          [4444],
    "PRIVILEGE_ESCALATION": [22],
    "LATERAL_MOVEMENT":     [445, 3389],
    "EXFILTRATION":         [443],
    "IMPACT":               [443],
}

_INTERNAL_IPS = ["10.0.0.10", "10.0.0.25", "10.0.0.50", "192.168.1.100", "192.168.1.200"]


async def full_breach_attack(
    source_ip: str | None = None,
    target_ip: str | None = None,
    **_kwargs: object,
) -> AsyncIterator[dict]:
    """
    Simulates a complete attacker kill chain where the attacker succeeds.
    Each stage emits 2-4 events tagged with breach_stage.
    If the attacker IP gets blocked mid-chain (by the auto-response engine),
    the scenario aborts immediately — the block works.
    """
    from response.actions import is_ip_blocked  # imported here to avoid circular import

    attacker_ip = source_ip or _ip()
    entry_target = target_ip or _ip()
    country = _stable_country_for_ip(attacker_ip)

    for stage_name, attack_type, description in _BREACH_STAGES:
        # Check block status before each stage — auto-response may have blocked us
        if is_ip_blocked(attacker_ip):
            print(f"[breach] attacker {attacker_ip} was blocked — aborting chain at {stage_name}")
            return

        ports = _BREACH_PORTS.get(stage_name, [443])
        dest_ip = random.choice(_INTERNAL_IPS) if stage_name == "LATERAL_MOVEMENT" else entry_target

        event_count = random.randint(2, 4)
        for i in range(event_count):
            # Re-check mid-stage too
            if is_ip_blocked(attacker_ip):
                print(f"[breach] attacker {attacker_ip} blocked mid-stage {stage_name} — aborting")
                return

            port = random.choice(ports)
            yield {
                "timestamp": _ts(),
                "source_ip": attacker_ip,
                "destination_ip": dest_ip,
                "destination_port": port,
                "protocol": "TCP" if port not in (80, 443, 8080) else "HTTP",
                "event_type": "breach",
                "username": "root" if stage_name in ("INITIAL_ACCESS", "PRIVILEGE_ESCALATION") else None,
                "status": "success",
                "bytes_transferred": random.randint(500, 50000),
                "country": country,
                "is_attack": True,
                "breach_stage": stage_name,
                "breach_stage_index": _BREACH_STAGES.index((stage_name, attack_type, description)),
                "breach_description": description,
                "breach_attacker_wins": True,
                "attack_type": attack_type,
                "payload": f"[{stage_name}] {description} (event {i+1}/{event_count})",
            }
            await asyncio.sleep(1.5)

        await asyncio.sleep(2.0)
