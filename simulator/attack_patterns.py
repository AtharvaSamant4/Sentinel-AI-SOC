from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import random
from typing import Optional

from faker import Faker

from models.event import SecurityEvent

PROTOCOLS = ["TCP", "UDP", "HTTP", "SSH"]
EVENT_TYPES = ["login", "request", "connection"]
STATUSES = ["success", "failure"]
COMMON_PORTS = [22, 53, 80, 443, 8080, 3306, 5432]
HOSTILE_COUNTRIES = ["RU", "CN", "IR", "KP", "BR"]


@dataclass
class EventContext:
    faker: Faker = field(default_factory=Faker)
    usernames: list[str] = field(default_factory=list)
    countries: list[str] = field(default_factory=list)
    scan_target_ip: str = field(default_factory=lambda: _random_ip())
    scan_source_ip: str = field(default_factory=lambda: _random_ip())
    scan_ports: list[int] = field(default_factory=list)
    scan_index: int = 0
    brute_source_ip: str = field(default_factory=lambda: _random_ip())
    brute_target_ip: str = field(default_factory=lambda: _random_ip())
    brute_username: str = ""
    brute_remaining_failures: int = 0
    brute_country: str = "RU"
    normal_source_ips: list[str] = field(default_factory=list)
    normal_source_country: dict[str, str] = field(default_factory=dict)
    normal_destination_ips: list[str] = field(default_factory=list)
    hostile_country_index: int = 0
    hostile_source_ips: dict[str, list[str]] = field(default_factory=dict)
    hostile_source_index: dict[str, int] = field(default_factory=dict)
    sqli_target_ip: str = field(default_factory=lambda: _random_ip())
    c2_target_ip: str = field(default_factory=lambda: _random_ip())

    def __post_init__(self) -> None:
        if not self.usernames:
            self.usernames = [self.faker.user_name() for _ in range(300)]
        if not self.countries:
            self.countries = [self.faker.country_code() for _ in range(120)]
        if not self.normal_source_ips:
            self.normal_source_ips = [_random_ip() for _ in range(30)]
        if not self.normal_source_country:
            self.normal_source_country = {
                ip: random.choice(self.countries) for ip in self.normal_source_ips
            }
        if not self.normal_destination_ips:
            self.normal_destination_ips = [_random_ip() for _ in range(20)]
        if not self.hostile_source_ips:
            self.hostile_source_ips = {
                country: [_random_ip() for _ in range(6)] for country in HOSTILE_COUNTRIES
            }
        if not self.hostile_source_index:
            self.hostile_source_index = {country: 0 for country in HOSTILE_COUNTRIES}
        self._reset_port_scan()
        self._reset_bruteforce()

    def next_hostile_country(self) -> str:
        country = HOSTILE_COUNTRIES[self.hostile_country_index % len(HOSTILE_COUNTRIES)]
        self.hostile_country_index += 1
        return country

    def source_ip_for_country(self, country: str) -> str:
        pool = self.hostile_source_ips.get(country, [_random_ip()])
        index = self.hostile_source_index.get(country, 0)
        source_ip = pool[index % len(pool)]
        self.hostile_source_index[country] = index + 1
        return source_ip

    def _reset_port_scan(self) -> None:
        self.scan_target_ip = _random_ip()
        self.scan_country = self.next_hostile_country()
        self.scan_source_ip = self.source_ip_for_country(self.scan_country)
        self.scan_ports = random.sample(range(1, 65535), 40)
        self.scan_index = 0

    def _reset_bruteforce(self) -> None:
        self.brute_country = self.next_hostile_country()
        self.brute_source_ip = self.source_ip_for_country(self.brute_country)
        self.brute_target_ip = _random_ip()
        self.brute_username = random.choice(self.usernames)
        self.brute_remaining_failures = random.randint(6, 18)


def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_normal_event(context: Optional[EventContext] = None) -> dict:
    ctx = context or EventContext()
    source_ip = random.choice(ctx.normal_source_ips)
    country = ctx.normal_source_country.get(source_ip)
    if not country:
        country = random.choice(ctx.countries)
        ctx.normal_source_country[source_ip] = country

    event_type = random.choices(EVENT_TYPES, weights=[0.1, 0.55, 0.35], k=1)[0]

    username = None
    protocol = random.choices(PROTOCOLS, weights=[0.4, 0.15, 0.3, 0.15], k=1)[0]
    destination_port = random.choice(COMMON_PORTS)
    status = random.choices(STATUSES, weights=[0.98, 0.02], k=1)[0]

    if event_type == "login":
        username = random.choice(ctx.usernames)
        protocol = "SSH"
        destination_port = 22
    elif event_type == "request":
        protocol = "HTTP"
        destination_port = random.choice([80, 443, 8080])

    event = SecurityEvent(
        timestamp=_timestamp(),
        source_ip=source_ip,
        destination_ip=random.choice(ctx.normal_destination_ips),
        destination_port=destination_port,
        protocol=protocol,
        event_type=event_type,
        username=username,
        status=status,
        bytes_transferred=random.randint(200, 16000),
        country=country,
        is_attack=False,
    )
    return event.as_dict()


def generate_brute_force_attack(context: Optional[EventContext] = None) -> dict:
    ctx = context or EventContext()
    if ctx.brute_remaining_failures <= 0:
        ctx._reset_bruteforce()

    ctx.brute_remaining_failures -= 1
    status = "failure"

    # Occasionally emit a successful compromise event after a burst of failures.
    if ctx.brute_remaining_failures == 0 and random.random() < 0.35:
        status = "success"

    event = SecurityEvent(
        timestamp=_timestamp(),
        source_ip=ctx.brute_source_ip,
        destination_ip=ctx.brute_target_ip,
        destination_port=22,
        protocol="SSH",
        event_type="login",
        username=ctx.brute_username,
        status=status,
        bytes_transferred=random.randint(60, 1300),
        country=ctx.brute_country,
        is_attack=True,
    )
    data = event.as_dict()
    data["attack_tag"] = "Brute Force"
    return data


def generate_port_scan(context: Optional[EventContext] = None) -> dict:
    ctx = context or EventContext()

    if ctx.scan_index >= len(ctx.scan_ports):
        ctx._reset_port_scan()

    destination_port = ctx.scan_ports[ctx.scan_index]
    ctx.scan_index += 1

    event = SecurityEvent(
        timestamp=_timestamp(),
        source_ip=ctx.scan_source_ip,
        destination_ip=ctx.scan_target_ip,
        destination_port=destination_port,
        protocol=random.choice(["TCP", "UDP"]),
        event_type="connection",
        username=None,
        status="failure",
        bytes_transferred=random.randint(40, 500),
        country=ctx.scan_country,
        is_attack=True,
    )
    data = event.as_dict()
    data["attack_tag"] = "Port Scan"
    return data


def generate_sql_injection_attack(context: Optional[EventContext] = None) -> dict:
    ctx = context or EventContext()
    country = ctx.next_hostile_country()
    source_ip = ctx.source_ip_for_country(country)
    target_ip = ctx.sqli_target_ip
    payload = random.choice(
        [
            "' OR 1=1 --",
            "admin' UNION SELECT password FROM users --",
            "1; DROP TABLE sessions; --",
        ]
    )

    event = SecurityEvent(
        timestamp=_timestamp(),
        source_ip=source_ip,
        destination_ip=target_ip,
        destination_port=443,
        protocol="HTTP",
        event_type="request",
        username=random.choice(ctx.usernames),
        status="failure",
        bytes_transferred=random.randint(1200, 6400),
        country=country,
        is_attack=True,
    )
    data = event.as_dict()
    data["payload"] = payload
    data["attack_tag"] = "SQL Injection"
    return data


def generate_c2_beacon_attack(context: Optional[EventContext] = None) -> dict:
    ctx = context or EventContext()
    country = ctx.next_hostile_country()
    source_ip = ctx.source_ip_for_country(country)
    target_ip = ctx.c2_target_ip

    event = SecurityEvent(
        timestamp=_timestamp(),
        source_ip=source_ip,
        destination_ip=target_ip,
        destination_port=443,
        protocol=random.choice(["TCP", "HTTP"]),
        event_type="connection",
        username=None,
        status="success",
        bytes_transferred=random.randint(80, 280),
        country=country,
        is_attack=True,
    )
    data = event.as_dict()
    data["c2_signal"] = True
    data["beacon_interval_seconds"] = random.choice([30, 45, 60])
    data["attack_tag"] = "C2 Beacon"
    return data
