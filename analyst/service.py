from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from analyst.context_builder import build_auto_analysis_message, build_context, build_prompt
from analyst.gemini_client import GeminiClient
from analyst.ip_reputation import get_ip_reputation


class AnalystService:
    _INCIDENT_SECTION_ORDER = (
        "EXECUTIVE SUMMARY",
        "TIMELINE OF EVENTS",
        "ATTACK VECTORS IDENTIFIED",
        "ASSETS AT RISK",
        "AUTOMATED ACTIONS TAKEN",
        "RECOMMENDED NEXT STEPS",
        "RAW EVENT LOG",
    )

    def __init__(
        self,
        cooldown_seconds: int = 12,
        cache_ttl_seconds: int = 180,
        auto_debounce_seconds: int = 30,
    ) -> None:
        self._client = GeminiClient()
        self._cooldown_seconds = cooldown_seconds
        self._cache_ttl_seconds = cache_ttl_seconds
        self._auto_debounce_seconds = auto_debounce_seconds

        self._last_call_by_key: dict[str, float] = {}
        self._analysis_cache: dict[str, tuple[str, float]] = {}
        self._inflight: set[str] = set()
        self._last_auto_analysis_at = 0.0
        self._lock = asyncio.Lock()

    async def generate_counterfactual(self, threat: dict[str, Any], blocked_ip: str) -> str:
        target_asset = self._target_asset(threat)
        user_message = (
            f"An automated response just blocked {blocked_ip} which was executing "
            f"a {threat.get('attack_type', 'UNKNOWN')} attack with risk score "
            f"{int(float(threat.get('risk_score', 0) or 0))}/100 targeting {target_asset}.\n\n"
            "If SENTINEL had NOT blocked this IP, what would most likely have happened?\n"
            "Respond in exactly this format with no extra text:\n\n"
            "NEXT MOVE: [one sentence - most likely attacker next action]\n"
            "AT RISK: [one sentence - specific asset or data most at risk]\n"
            "TIME TO BREACH: [realistic estimate like '15-45 minutes' or '2-4 hours']\n"
            "BLAST RADIUS: [one sentence - potential damage scope]"
        )

        try:
            base_prompt = build_prompt(build_context(threat))
            prompt = f"{base_prompt}\n\n{user_message}"
            text = await asyncio.to_thread(self._client.generate_analysis, prompt)
            cleaned = " ".join(self._clean_model_output(str(text)).split())
            return cleaned[:420]
        except Exception:
            return (
                "NEXT MOVE: Continued credential-stuffing and service probing against exposed interfaces.\n"
                "AT RISK: Internet-facing authentication systems and linked privileged accounts.\n"
                "TIME TO BREACH: 15-45 minutes.\n"
                "BLAST RADIUS: Account takeover risk with possible lateral movement into sensitive internal services."
            )

    async def generate_incident_report(self, session_data: dict[str, Any]) -> str:
        events = list(session_data.get("events", []))
        attack_events = [event for event in events if self._is_confirmed_attack_event(event)]
        actions = list(session_data.get("actions", []))
        generated_at = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        highest_severity = self._highest_severity(attack_events)

        if not attack_events:
            return (
                "INCIDENT REPORT - SENTINEL AI-SOC\n"
                f"Generated: {generated_at}\n"
                "Severity: LOW\n\n"
                "EXECUTIVE SUMMARY\n"
                "No confirmed attack activity has been observed since the current server session started. "
                "Only routine or low-risk telemetry has been recorded so far.\n\n"
                "TIMELINE OF EVENTS\n"
                "- No confirmed attack events in current session history.\n\n"
                "ATTACK VECTORS IDENTIFIED\n"
                "- None\n\n"
                "ASSETS AT RISK\n"
                "- No specific asset identified as under active attack\n\n"
                "AUTOMATED ACTIONS TAKEN\n"
                "- No automated containment actions required\n\n"
                "RECOMMENDED NEXT STEPS\n"
                "1. Continue monitoring baseline traffic for anomalies.\n"
                "2. Validate alerting pipeline health and dashboards.\n"
                "3. Keep attack simulation controls ready for validation drills."
            )

        event_lines = "\n".join(self._event_line(event) for event in attack_events[-40:])
        action_lines = "\n".join(self._action_line(action) for action in actions[-40:])
        raw_log_table = self._build_raw_log_table(attack_events)

        # Compute summary stats for the prompt
        unique_ips = sorted({str(e.get("source_ip", "")) for e in attack_events if e.get("source_ip")})
        unique_types = sorted({str(e.get("attack_type", "")).replace("_", " ").title() for e in attack_events if str(e.get("attack_type", "NORMAL")).upper() != "NORMAL"})
        blocked_ips = [a for a in actions if str(a.get("action", "")) == "block_ip" and str(a.get("status", "")).lower() == "success"]
        tickets = [a for a in actions if str(a.get("action", "")) in {"create_ticket", "create_alert"} and str(a.get("status", "")).lower() == "success"]

        user_prompt = (
            "You are a senior SOC analyst writing a formal Incident Response Report.\n"
            "Write a comprehensive, professional report. Do NOT use markdown symbols (*, **, #, ```).\n"
            "Use plain text only. Use this EXACT structure with these EXACT section headers:\n\n"
            "INCIDENT REPORT - SENTINEL AI-SOC\n"
            f"Generated: {generated_at}\n"
            f"Severity: {highest_severity}\n"
            f"Total Attack Events: {len(attack_events)}\n"
            f"Unique Attacker IPs: {len(unique_ips)}\n"
            f"IPs Blocked: {len(blocked_ips)}\n"
            f"Tickets Created: {len(tickets)}\n\n"
            "EXECUTIVE SUMMARY\n"
            "(3-4 sentences suitable for a CEO. Describe what happened, the scale, and whether it was contained.)\n\n"
            "TIMELINE OF EVENTS\n"
            "(Chronological bullet list. Each bullet: timestamp, event type, source IP, action taken. Min 5 bullets.)\n\n"
            "ATTACK VECTORS IDENTIFIED\n"
            "(One bullet per unique attack type. Format: AttackType - Source IP(s) - MITRE Technique - Description)\n\n"
            "ASSETS AT RISK\n"
            "(One bullet per targeted system/IP:port. Include protocol and risk level.)\n\n"
            "AUTOMATED ACTIONS TAKEN\n"
            "(One bullet per action with timestamp and outcome. Include all IP blocks, account locks, tickets.)\n\n"
            "RECOMMENDED NEXT STEPS\n"
            "(Numbered list of 5 specific, actionable steps for the security team.)\n\n"
            "Do not add any other sections. Do not include the RAW EVENT LOG section — that is appended separately.\n\n"
            f"EVIDENCE - Attack events ({len(attack_events)} total, showing last 40):\n"
            f"{event_lines or '- No recent events available'}\n\n"
            f"EVIDENCE - Automated response actions:\n"
            f"{action_lines or '- No automated actions recorded'}\n\n"
            f"Session context:\n"
            f"- Attack types observed: {', '.join(unique_types) if unique_types else 'None'}\n"
            f"- Attacking IPs: {', '.join(unique_ips[:15]) if unique_ips else 'None'}\n"
            f"- Highest severity reached: {highest_severity}"
        )

        try:
            prompt = user_prompt
            report = await asyncio.to_thread(self._client.generate_analysis, prompt)
            cleaned = self._clean_model_output(report)
            formatted = self._enforce_incident_report_format(
                cleaned,
                generated_at=generated_at,
                severity=highest_severity,
                attack_events=attack_events,
                actions=actions,
            )
            # Append raw log table as appendix
            return (
                formatted
                + "\n\nRAW EVENT LOG\n"
                + raw_log_table
            )
        except Exception:
            fallback = (
                "INCIDENT REPORT - SENTINEL AI-SOC\n"
                f"Generated: {generated_at}\n"
                f"Severity: {highest_severity}\n\n"
                "EXECUTIVE SUMMARY\n"
                "SENTINEL identified a coordinated intrusion attempt and contained key attacker paths quickly. "
                "Automated controls reduced immediate business risk while investigation continues.\n\n"
                "TIMELINE OF EVENTS\n"
                "- Initial suspicious traffic detected and classified as high risk.\n"
                "- Automated playbooks blocked malicious sources and created alerts.\n"
                "- Analyst workflow enriched event context for rapid triage.\n\n"
                "ATTACK VECTORS IDENTIFIED\n"
                "- Brute Force . external source . T1110\n\n"
                "ASSETS AT RISK\n"
                "- Internet-facing authentication service\n\n"
                "AUTOMATED ACTIONS TAKEN\n"
                "- Source IP blocked\n"
                "- Incident ticket created\n\n"
                "RECOMMENDED NEXT STEPS\n"
                "1. Verify account integrity and force credential rotation.\n"
                "2. Review host telemetry for lateral movement indicators.\n"
                "3. Maintain enhanced monitoring for 24 hours."
            )
            return fallback

    async def generate_persistence_insight(self, threat: dict[str, Any], dwell_time: str) -> str:
        ip = str(threat.get("source_ip", "unknown"))
        user_prompt = (
            f"IP {ip} has been active in our network for {dwell_time}. This level of "
            "persistence is unusual. What does this indicate about attacker intent, "
            "and what should we do to hunt for any foothold they may have established?"
        )
        try:
            base_prompt = build_prompt(build_context(threat))
            prompt = f"{base_prompt}\n\n{user_prompt}"
            text = await asyncio.to_thread(self._client.generate_analysis, prompt)
            return " ".join(self._clean_model_output(str(text)).split())
        except Exception:
            return (
                "Sustained activity suggests deliberate foothold establishment and credential reuse attempts. "
                "Prioritize host triage for the targeted asset, review auth and process logs, "
                "hunt for persistence artifacts, and isolate suspicious endpoints for containment."
            )

    async def generate_campaign_assessment(
        self,
        events: list[dict[str, Any]],
        vectors: list[str],
        geo_list: list[str],
    ) -> str:
        reference = self._reference_threat(events)
        base_prompt = build_prompt(build_context(reference))
        vector_count = len(vectors)
        list_of_attack_types = ", ".join(vectors)
        geo_text = ", ".join(geo_list) if geo_list else "Unknown"

        user_prompt = (
            f"SENTINEL has detected {vector_count} simultaneous attack vectors in the last "
            f"10 minutes: {list_of_attack_types}. Source countries: {geo_text}.\n\n"
            "Assess: Is this a coordinated campaign or coincidence? What is the "
            "likely objective? Which asset is the primary target? What is the "
            "recommended immediate response? Answer in 4 sentences max."
        )

        try:
            prompt = f"{base_prompt}\n\n{user_prompt}"
            text = await asyncio.to_thread(self._client.generate_analysis, prompt)
            return " ".join(self._clean_model_output(str(text)).split())
        except Exception:
            return (
                "This pattern is likely coordinated rather than coincidental because multiple attack vectors are active in a compressed window. "
                "The probable objective is rapid credential compromise followed by persistent access for data theft. "
                "The primary target is the exposed authentication and adjacent application tier. "
                "Immediately isolate high-risk sources, enforce account protections, and begin host-level threat hunting for persistence artifacts."
            )

    async def generate_board_report(self, session_data: dict[str, Any]) -> str:
        events = list(session_data.get("events", []))
        attack_events = [event for event in events if self._is_confirmed_attack_event(event)]
        actions = list(session_data.get("actions", []))

        if not attack_events:
            return (
                "- THREAT LEVEL: Low in the current session because no confirmed attacks were observed.\n"
                "- WHAT HAPPENED: Only routine or low-risk telemetry was seen after restart.\n"
                "- DID WE STOP IT: No containment actions were needed because no active attack was confirmed.\n"
                "- WHAT'S AT RISK: No specific business-critical asset is currently under active attack.\n"
                "- WHAT WE'RE DOING: We are maintaining continuous monitoring and validating alert readiness.\n"
                "BOTTOM LINE: Environment is stable right now, with monitoring still active."
            )

        attack_types = sorted(
            {
                str(event.get("attack_type", "UNKNOWN")).replace("_", " ").title()
                for event in attack_events
                if str(event.get("attack_type", "NORMAL")).upper() != "NORMAL"
            }
        )
        blocked_count = sum(
            1
            for action in actions
            if str(action.get("action", "")) == "block_ip"
            and str(action.get("status", "")).lower() == "success"
        )
        asset_targets = sorted(
            {
                f"{event.get('destination_ip', 'unknown')}:{int(event.get('destination_port', 0) or 0)}"
                if int(event.get("destination_port", 0) or 0) > 0
                else str(event.get("destination_ip", "unknown"))
                for event in attack_events
            }
        )
        highest_severity = self._highest_severity(attack_events)

        user_prompt = (
            "Generate a 5-bullet executive board report summarizing this "
            "security session. Write for a non-technical CEO or board member. "
            "No jargon. Each bullet must be one clear sentence. Format:\n\n"
            "- THREAT LEVEL: [one sentence on overall severity]\n"
            "- WHAT HAPPENED: [one sentence on the main attack types seen]\n"
            "- DID WE STOP IT: [one sentence on whether attacks were blocked]\n"
            "- WHAT'S AT RISK: [one sentence on which systems/data were targeted]\n"
            "- WHAT WE'RE DOING: [one sentence on next steps]\n\n"
            "After the 5 bullets, add one final line:\n"
            "BOTTOM LINE: [one sentence that a board member should remember]\n\n"
            "Do not use markdown symbols such as * or **. Use plain text only.\n\n"
            f"Live session severity: {highest_severity}\n"
            f"Observed attack types: {', '.join(attack_types) if attack_types else 'None observed'}\n"
            f"Successful automated IP blocks: {blocked_count}\n"
            f"Targeted assets: {', '.join(asset_targets[:10]) if asset_targets else 'Unknown'}"
        )

        try:
            prompt = user_prompt
            text = await asyncio.to_thread(self._client.generate_analysis, prompt)
            cleaned = self._clean_model_output(str(text))
            return self._enforce_board_report_format(cleaned, highest_severity)
        except Exception:
            return (
                "- THREAT LEVEL: We saw high-risk hostile activity that required immediate containment.\n"
                "- WHAT HAPPENED: Multiple attack patterns appeared, including credential abuse and reconnaissance behavior.\n"
                "- DID WE STOP IT: Automated defenses blocked malicious sources and reduced immediate impact.\n"
                "- WHAT'S AT RISK: Internet-facing authentication and application systems were the main targets.\n"
                "- WHAT WE'RE DOING: We are maintaining enhanced monitoring, validating account integrity, and checking for persistence.\n"
                "BOTTOM LINE: The attack pressure was real, but controls worked and follow-up containment is in progress."
            )

    async def enrich_threat(self, threat: dict[str, Any]) -> dict[str, Any]:
        risk_score = float(threat.get("risk_score", 0) or 0)
        if risk_score < 75:
            return threat

        if str(threat.get("severity", "LOW")).upper() == "HIGH":
            source_ip = str(threat.get("source_ip", "")).strip()
            if source_ip and source_ip.lower() != "unknown":
                threat["ip_intel"] = await asyncio.to_thread(get_ip_reputation, source_ip)

        threat["auto_detected"] = True
        threat["analysis_mode"] = "auto"

        key = self._key_for_threat(threat)
        now = time.time()

        async with self._lock:
            cached = self._analysis_cache.get(key)
            if cached and (now - cached[1]) <= self._cache_ttl_seconds:
                threat["analysis"] = cached[0]
                return threat

            threat["analysis"] = self._fallback_analysis(threat)

            if (now - self._last_auto_analysis_at) < self._auto_debounce_seconds:
                threat["analysis_mode"] = "auto_debounced"
                return threat

            last_call = self._last_call_by_key.get(key, 0.0)
            on_cooldown = (now - last_call) < self._cooldown_seconds
            if on_cooldown or key in self._inflight:
                threat["analysis_mode"] = "auto_cooldown"
                return threat

            self._last_call_by_key[key] = now
            self._inflight.add(key)
            snapshot = dict(threat)

        # Do the model call immediately so the current threat event carries analysis to the UI.
        analysis = await self._generate_analysis(snapshot)

        async with self._lock:
            self._analysis_cache[key] = (analysis, time.time())
            self._last_auto_analysis_at = time.time()
            self._inflight.discard(key)

        threat["analysis"] = analysis
        return threat

    async def _generate_analysis(self, threat_snapshot: dict[str, Any]) -> str:
        try:
            base_prompt = build_prompt(build_context(threat_snapshot))
            auto_message = build_auto_analysis_message(threat_snapshot)
            prompt = f"{base_prompt}\n\nAuto-detected threat request:\n{auto_message}"
            analysis = await asyncio.to_thread(self._client.generate_analysis, prompt)
            analysis = self._clean_model_output(str(analysis))
        except Exception:
            analysis = self._fallback_analysis(threat_snapshot)
        return analysis

    async def generate_manual_analysis(
        self,
        threat: dict[str, Any] | None,
        user_query: str,
    ) -> str:
        query = str(user_query or "").strip()
        if not query:
            return "Please enter a question for the analyst."

        snapshot = dict(threat or self._reference_threat([]))
        try:
            base_prompt = build_prompt(build_context(snapshot))
            prompt = (
                f"{base_prompt}\n\n"
                "User question:\n"
                f"{query}\n\n"
                "Answer in plain English with direct, actionable guidance. "
                "Use plain text only and avoid markdown symbols."
            )
            text = await asyncio.to_thread(self._client.generate_analysis, prompt)
            cleaned = self._clean_model_output(str(text))
            return cleaned or "No analyst response was generated."
        except Exception as exc:
            return self._fallback_manual_analysis(snapshot, query, error=str(exc))

    @staticmethod
    def _key_for_threat(threat: dict[str, Any]) -> str:
        attack_type = str(threat.get("attack_type", "UNKNOWN"))
        source_ip = str(threat.get("source_ip", "unknown"))
        return f"{attack_type}:{source_ip}"

    @staticmethod
    def _fallback_analysis(threat: dict[str, Any]) -> str:
        attack_type = str(threat.get("attack_type", "UNKNOWN")).upper().strip()
        attempted = str(threat.get("attempted_attack_type", "")).upper().strip()
        label = attempted if attack_type == "BLOCKED_SOURCE" and attempted else attack_type
        source_ip = str(threat.get("source_ip", "unknown"))
        target = str(threat.get("destination_ip", "unknown"))
        port = int(threat.get("destination_port", 0) or 0)
        risk = int(float(threat.get("risk_score", 0) or 0))
        severity = str(threat.get("severity", "LOW"))
        mitre = threat.get("mitre", {}) if isinstance(threat.get("mitre"), dict) else {}
        technique = str(mitre.get("technique", "N/A"))

        attack_text = label.replace("_", " ").title() if label else "Unknown activity"
        target_text = f"{target}:{port}" if port > 0 else target

        if attack_type == "BLOCKED_SOURCE":
            return (
                f"Blocked retry detected for {attack_text} from {source_ip}. "
                f"Risk {risk}/100 ({severity}), MITRE {technique}. "
                "Firewall deny appears effective. Verify no pre-block access on target systems and monitor for source rotation."
            )

        return (
            f"High-risk {attack_text} activity detected from {source_ip} toward {target_text}. "
            f"Risk {risk}/100 ({severity}), MITRE {technique}. "
            "Contain source, validate target integrity, and monitor for follow-on movement while automated analysis refreshes."
        )

    @classmethod
    def _fallback_manual_analysis(
        cls,
        threat: dict[str, Any],
        user_query: str,
        error: str | None = None,
    ) -> str:
        base = cls._fallback_analysis(threat)
        source_ip = str(threat.get("source_ip", "unknown"))
        country = str(threat.get("country", "XX"))
        risk = int(float(threat.get("risk_score", 0) or 0))
        query = str(user_query or "").strip()
        reason = str(error or "").replace("\n", " ").strip()
        if len(reason) > 220:
            reason = f"{reason[:217]}..."
        reason_text = f" Provider status: {reason}." if reason else ""

        if query:
            return (
                "Analyst response generated using deterministic fallback."
                f"{reason_text} "
                f"Question: '{query}'. Current signal: source {source_ip} from {country}, risk {risk}/100. "
                f"{base}"
            )

        return f"Analyst response generated using deterministic fallback.{reason_text} {base}"

    @staticmethod
    def _target_asset(threat: dict[str, Any]) -> str:
        destination_ip = str(threat.get("destination_ip", "unknown"))
        destination_port = int(threat.get("destination_port", 0) or 0)
        if destination_port > 0:
            return f"{destination_ip}:{destination_port}"
        return destination_ip

    @staticmethod
    def _highest_severity(events: list[dict[str, Any]]) -> str:
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        current = "LOW"
        for event in events:
            severity = str(event.get("severity", "LOW")).upper()
            if rank.get(severity, 0) > rank.get(current, 0):
                current = severity
        return current

    @staticmethod
    def _reference_threat(events: list[dict[str, Any]]) -> dict[str, Any]:
        if not events:
            return {
                "attack_type": "UNKNOWN",
                "risk_score": 0,
                "severity": "LOW",
                "source_ip": "unknown",
                "destination_ip": "unknown",
                "destination_port": 0,
                "anomaly_score": 0.0,
                "reason": "No recent events",
            }

        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        ordered = sorted(
            events,
            key=lambda event: (
                rank.get(str(event.get("severity", "LOW")).upper(), 0),
                float(event.get("risk_score", 0) or 0),
            ),
            reverse=True,
        )
        return dict(ordered[0])

    @staticmethod
    def _event_line(event: dict[str, Any]) -> str:
        ts = str(event.get("timestamp", "unknown"))[:19].replace("T", " ")
        attack_type = str(event.get("attack_type", "UNKNOWN")).replace("_", " ")
        source_ip = str(event.get("source_ip", "unknown"))
        dest_ip = str(event.get("destination_ip", "unknown"))
        port = int(event.get("destination_port", 0) or 0)
        severity = str(event.get("severity", "LOW")).upper()
        risk = int(float(event.get("risk_score", 0) or 0))
        country = str(event.get("country", "XX"))
        mitre = event.get("mitre", {}) if isinstance(event.get("mitre", {}), dict) else {}
        technique = str(mitre.get("technique", "N/A"))
        dest = f"{dest_ip}:{port}" if port else dest_ip
        return f"- [{ts}] {attack_type} | {source_ip} ({country}) → {dest} | Risk {risk}/100 | {severity} | {technique}"

    @staticmethod
    def _action_line(action: dict[str, Any]) -> str:
        ts = str(action.get("timestamp", "unknown"))[:19].replace("T", " ")
        action_name = str(action.get("action", "unknown")).replace("_", " ").upper()
        target = str(action.get("target", "unknown"))
        status = str(action.get("status", "unknown")).upper()
        return f"- [{ts}] {action_name} → {target} [{status}]"

    @staticmethod
    def _build_raw_log_table(events: list[dict[str, Any]]) -> str:
        """Build a compact raw log table for the appendix (up to 50 events)."""
        rows = []
        rows.append(f"{'#':<4} {'TIMESTAMP':<20} {'TYPE':<22} {'SOURCE IP':<16} {'DEST':<22} {'SEV':<9} {'RISK':<6} {'MITRE'}")
        rows.append("-" * 120)
        for i, event in enumerate(events[-50:], start=1):
            ts = str(event.get("timestamp", ""))[:19].replace("T", " ")
            atype = str(event.get("attack_type", "UNKNOWN")).replace("_", " ")[:20]
            src = str(event.get("source_ip", "unknown"))[:15]
            dest_ip = str(event.get("destination_ip", "unknown"))
            port = int(event.get("destination_port", 0) or 0)
            dest = (f"{dest_ip}:{port}" if port else dest_ip)[:20]
            sev = str(event.get("severity", "LOW")).upper()[:8]
            risk = str(int(float(event.get("risk_score", 0) or 0)))
            mitre = event.get("mitre", {}) if isinstance(event.get("mitre", {}), dict) else {}
            technique = str(mitre.get("technique", "N/A"))
            rows.append(f"{i:<4} {ts:<20} {atype:<22} {src:<16} {dest:<22} {sev:<9} {risk:<6} {technique}")
        return "\n".join(rows)

    @staticmethod
    def _truncate_words(text: str, max_words: int) -> str:
        words = str(text or "").split()
        if len(words) <= max_words:
            return str(text).strip()
        return " ".join(words[:max_words]).strip() + "..."

    @staticmethod
    def _is_confirmed_attack_event(event: dict[str, Any]) -> bool:
        if not isinstance(event, dict):
            return False

        attack_type = str(event.get("attack_type", "")).upper().strip()
        if attack_type in {"", "NORMAL", "SYSTEM"}:
            return False

        # Coordinated campaign and blocked-source are attack-context events.
        if attack_type in {"COORDINATED_CAMPAIGN", "BLOCKED_SOURCE"}:
            return True

        return bool(event.get("is_attack", False))

    @staticmethod
    def _clean_model_output(text: str) -> str:
        raw = str(text or "")
        if not raw.strip():
            return ""

        # Remove fenced code blocks wrappers if present.
        raw = raw.replace("```", "")

        # Remove common markdown heading markers.
        raw = re.sub(r"(?m)^\s{0,3}#{1,6}\s*", "", raw)

        # Convert markdown bullets to plain bullets.
        raw = re.sub(r"(?m)^\s*\*\s+", "- ", raw)

        # Remove emphasis markers like **text** or *text*.
        raw = raw.replace("**", "")
        raw = re.sub(r"\*(.*?)\*", r"\1", raw)

        # Remove prefatory wrappers often returned by LLMs.
        raw = re.sub(r"(?i)^\s*here('?| i)s\s+the\s+analysis[^:]*:\s*", "", raw)

        # Normalize spacing while preserving line breaks.
        lines = [re.sub(r"\s+", " ", line).strip() for line in raw.splitlines()]
        lines = [line for line in lines if line]
        return "\n".join(lines).strip()

    @classmethod
    def _enforce_incident_report_format(
        cls,
        text: str,
        generated_at: str,
        severity: str,
        attack_events: list[dict[str, Any]] | None = None,
        actions: list[dict[str, Any]] | None = None,
    ) -> str:
        cleaned = cls._clean_model_output(text)
        section_map = cls._extract_named_sections(cleaned, cls._INCIDENT_SECTION_ORDER)

        generated_match = re.search(r"(?im)^generated\s*:\s*(.+)$", cleaned)
        severity_match = re.search(r"(?im)^severity\s*:\s*(.+)$", cleaned)
        generated_value = generated_match.group(1).strip() if generated_match else generated_at
        severity_value = severity_match.group(1).strip().upper() if severity_match else severity.upper()

        # Compute stats for header
        evts = attack_events or []
        acts = actions or []
        unique_ips = len({str(e.get("source_ip", "")) for e in evts if e.get("source_ip")})
        blocked = sum(1 for a in acts if str(a.get("action", "")) == "block_ip" and str(a.get("status", "")).lower() == "success")
        tickets = sum(1 for a in acts if str(a.get("action", "")) in {"create_ticket", "create_alert"} and str(a.get("status", "")).lower() == "success")

        defaults = {
            "EXECUTIVE SUMMARY": "No executive summary available from current telemetry.",
            "TIMELINE OF EVENTS": "- No confirmed attack events in current session history.",
            "ATTACK VECTORS IDENTIFIED": "- None confirmed",
            "ASSETS AT RISK": "- Unknown from available telemetry",
            "AUTOMATED ACTIONS TAKEN": "- No automated actions recorded",
            "RECOMMENDED NEXT STEPS": (
                "1. Continue monitoring telemetry for attack confirmation.\n"
                "2. Validate affected asset ownership and exposure.\n"
                "3. Keep containment playbooks ready if risk escalates."
            ),
        }

        # Normalize list formatting for deterministic output.
        timeline = cls._normalize_list_block(
            section_map.get("TIMELINE OF EVENTS") or defaults["TIMELINE OF EVENTS"],
            numbered=False,
            fallback=defaults["TIMELINE OF EVENTS"],
        )
        vectors = cls._normalize_list_block(
            section_map.get("ATTACK VECTORS IDENTIFIED") or defaults["ATTACK VECTORS IDENTIFIED"],
            numbered=False,
            fallback=defaults["ATTACK VECTORS IDENTIFIED"],
        )
        assets = cls._normalize_list_block(
            section_map.get("ASSETS AT RISK") or defaults["ASSETS AT RISK"],
            numbered=False,
            fallback=defaults["ASSETS AT RISK"],
        )
        actions_text = cls._normalize_list_block(
            section_map.get("AUTOMATED ACTIONS TAKEN") or defaults["AUTOMATED ACTIONS TAKEN"],
            numbered=False,
            fallback=defaults["AUTOMATED ACTIONS TAKEN"],
        )
        next_steps = cls._normalize_list_block(
            section_map.get("RECOMMENDED NEXT STEPS") or defaults["RECOMMENDED NEXT STEPS"],
            numbered=True,
            fallback=defaults["RECOMMENDED NEXT STEPS"],
        )

        executive_summary = (
            section_map.get("EXECUTIVE SUMMARY") or defaults["EXECUTIVE SUMMARY"]
        ).strip()

        return (
            "INCIDENT REPORT - SENTINEL AI-SOC\n"
            f"Generated: {generated_value}\n"
            f"Severity: {severity_value}\n"
            f"Total Attack Events: {len(evts)}\n"
            f"Unique Attacker IPs: {unique_ips}\n"
            f"IPs Blocked: {blocked}\n"
            f"Tickets Created: {tickets}\n\n"
            "EXECUTIVE SUMMARY\n"
            f"{executive_summary}\n\n"
            "TIMELINE OF EVENTS\n"
            f"{timeline}\n\n"
            "ATTACK VECTORS IDENTIFIED\n"
            f"{vectors}\n\n"
            "ASSETS AT RISK\n"
            f"{assets}\n\n"
            "AUTOMATED ACTIONS TAKEN\n"
            f"{actions_text}\n\n"
            "RECOMMENDED NEXT STEPS\n"
            f"{next_steps}"
        )

    @classmethod
    def _enforce_board_report_format(cls, text: str, severity: str) -> str:
        cleaned = cls._clean_model_output(text)
        fields = {
            "THREAT LEVEL": f"Overall session severity is {severity.upper()}.",
            "WHAT HAPPENED": "No confirmed attack vector was identified from available telemetry.",
            "DID WE STOP IT": "No containment action was required in this session window.",
            "WHAT'S AT RISK": "No specific asset is confirmed under active attack.",
            "WHAT WE'RE DOING": "We are continuing monitoring and validating response readiness.",
            "BOTTOM LINE": "No confirmed attack at this time; maintain vigilance.",
        }

        for key in ["THREAT LEVEL", "WHAT HAPPENED", "DID WE STOP IT", "WHAT'S AT RISK", "WHAT WE'RE DOING", "BOTTOM LINE"]:
            pattern = re.compile(rf"(?im)^-?\s*{re.escape(key)}\s*:\s*(.+)$")
            match = pattern.search(cleaned)
            if match:
                fields[key] = match.group(1).strip().rstrip(".") + "."

        threat_level = fields["THREAT LEVEL"]
        what_happened = fields["WHAT HAPPENED"]
        did_we_stop_it = fields["DID WE STOP IT"]
        whats_at_risk = fields["WHAT'S AT RISK"]
        what_were_doing = fields["WHAT WE'RE DOING"]
        bottom_line = fields["BOTTOM LINE"]

        return (
            f"- THREAT LEVEL: {threat_level}\n"
            f"- WHAT HAPPENED: {what_happened}\n"
            f"- DID WE STOP IT: {did_we_stop_it}\n"
            f"- WHAT'S AT RISK: {whats_at_risk}\n"
            f"- WHAT WE'RE DOING: {what_were_doing}\n"
            f"BOTTOM LINE: {bottom_line}"
        )

    @staticmethod
    def _extract_named_sections(text: str, section_names: tuple[str, ...]) -> dict[str, str]:
        if not text.strip():
            return {}

        names_pattern = "|".join(re.escape(name) for name in section_names)
        splitter = re.compile(rf"(?m)^({names_pattern})\s*$")
        parts = splitter.split(text)
        if len(parts) <= 1:
            return {}

        result: dict[str, str] = {}
        for idx in range(1, len(parts), 2):
            name = parts[idx].strip().upper()
            body = parts[idx + 1].strip() if (idx + 1) < len(parts) else ""
            result[name] = body
        return result

    @staticmethod
    def _normalize_list_block(text: str, numbered: bool, fallback: str) -> str:
        source = str(text or "").strip()
        if not source:
            source = fallback

        items: list[str] = []
        for raw_line in source.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            line = re.sub(r"^[-*•]\s*", "", line)
            line = re.sub(r"^\d+[.)]\s*", "", line)
            line = line.strip()
            if line:
                items.append(line)

        if not items:
            items = [fallback]

        if numbered:
            return "\n".join(f"{i}. {item}" for i, item in enumerate(items[:5], start=1))

        return "\n".join(f"- {item}" for item in items[:8])


analyst_service = AnalystService(cooldown_seconds=12, cache_ttl_seconds=180, auto_debounce_seconds=30)
