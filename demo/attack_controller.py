from __future__ import annotations

import asyncio
from collections.abc import Callable
import ipaddress
import time
from typing import Any

from demo.scenarios import brute_force_attack, c2_beacon_attack, full_breach_attack, phishing_attack, port_scan_attack, sql_injection_attack
from response.actions import is_ip_blocked, normalize_ip
from simulator.generator import event_stream_service

ScenarioFactory = Callable[..., Any]


class AttackController:
    def __init__(self, cooldown_seconds: int = 0) -> None:
        self._active_attack_task: asyncio.Task | None = None
        self._active_attack_type: str | None = None
        self._cooldown_seconds = cooldown_seconds
        self._cooldown_until = 0.0
        self._state_lock = asyncio.Lock()
        self._scenarios: dict[str, ScenarioFactory] = {
            "bruteforce": brute_force_attack,
            "portscan": port_scan_attack,
            "phishing": phishing_attack,
            "sql_injection": sql_injection_attack,
            "c2_beacon": c2_beacon_attack,
            "full_breach": full_breach_attack,
        }

    async def trigger_attack(
        self,
        attack_type: str,
        source_ip: str | None = None,
        target_ip: str | None = None,
    ) -> dict:
        normalized = attack_type.strip().lower()
        scenario = self._scenarios.get(normalized)
        if scenario is None:
            return {"status": "error", "message": f"Unknown attack type: {attack_type}"}

        normalized_source_ip = normalize_ip(source_ip)
        if normalized_source_ip and not self._is_valid_ip(normalized_source_ip):
            return {
                "status": "error",
                "message": f"Invalid source_ip: {source_ip}",
            }

        normalized_target_ip = normalize_ip(target_ip)
        if normalized_target_ip and not self._is_valid_ip(normalized_target_ip):
            return {
                "status": "error",
                "message": f"Invalid target_ip: {target_ip}",
            }

        if normalized_source_ip and is_ip_blocked(normalized_source_ip):
            return {
                "status": "blocked",
                "message": f"Source IP {normalized_source_ip} is blocked by SOC response policy",
                "source_ip": normalized_source_ip,
                "attack": normalized,
            }

        async with self._state_lock:
            now = time.time()
            if now < self._cooldown_until:
                wait_seconds = int(self._cooldown_until - now)
                return {
                    "status": "cooldown",
                    "message": f"System cooling down. Try again in {wait_seconds}s",
                }

            if self._active_attack_task and not self._active_attack_task.done():
                return {
                    "status": "running",
                    "message": f"{self._active_attack_type or 'attack'} already in progress",
                }

            task = asyncio.create_task(
                self._run_scenario(
                    normalized,
                    scenario,
                    source_ip=(normalized_source_ip or None),
                    target_ip=(normalized_target_ip or None),
                ),
                name=f"demo-{normalized}",
            )
            self._active_attack_task = task
            self._active_attack_type = normalized
        return {
            "status": "started",
            "attack": normalized,
            "source_ip": normalized_source_ip or "auto",
            "target_ip": normalized_target_ip or "auto",
        }

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    async def _run_scenario(
        self,
        attack_type: str,
        scenario_factory: ScenarioFactory,
        source_ip: str | None = None,
        target_ip: str | None = None,
    ) -> None:
        print(f"[demo] attack started: {attack_type}")
        event_stream_service.suspend_background(25)
        try:
            async for event in scenario_factory(source_ip=source_ip, target_ip=target_ip):
                await event_stream_service.inject_event(event)
        finally:
            print(f"[demo] attack completed: {attack_type}")
            async with self._state_lock:
                self._active_attack_type = None
                self._active_attack_task = None
                self._cooldown_until = time.time() + self._cooldown_seconds


attack_controller = AttackController()
