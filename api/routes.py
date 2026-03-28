"""
api/routes.py
-------------
All REST routes for SENTINEL AI-SOC.

Registered via ``app.include_router(router)`` in api/main.py.
Every endpoint returns a consistent envelope:

    { "status": "success" | "error", "data": ... }

The three previously-missing endpoints are marked NEW below:
  POST /api/detect              – run detection on a single submitted event
  POST /api/response/trigger    – manually fire a response for a threat
  POST /api/response/rollback   – roll back a previously executed action
"""

from __future__ import annotations

import asyncio
import aiohttp
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from pydantic.networks import IPvAnyAddress

from analyst.gemini_client import GeminiClient
from analyst.service import analyst_service
from db.store import query_audit_log, query_threats
from demo.attack_controller import attack_controller
from detection.service import detection_service
from intelligence.log_query_service import log_query_service
from intelligence.service import intelligence_service
from nlp.service import classify_email
from response.operator import (
    approve_threat,
    get_all_threats,
    get_override_mode,
    get_pending_threats,
    reject_threat,
    set_override_mode,
)
from response.actions import unblock_ip, blocked_ips, block_ip
from response.service import response_service
from simulator.generator import event_stream_service

router = APIRouter()

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AttackRequest(BaseModel):
    type: str
    source_ip: IPvAnyAddress | None = None
    target_ip: IPvAnyAddress | None = None


class LogsQueryRequest(BaseModel):
    query: str
    event_history: list[dict] | None = None


class ReportRequest(BaseModel):
    events: list[dict] | None = None
    actions: list[dict] | None = None


class PersistenceInsightRequest(BaseModel):
    source_ip: str
    dwell_time: str
    threat: dict | None = None


class AnalystQueryRequest(BaseModel):
    query: str
    threat: dict | None = None


class PhishingClassifyRequest(BaseModel):
    subject: str = ""
    body: str = ""


class ThreatDecisionRequest(BaseModel):
    threat_id: str
    operator: str = "analyst"


class OverrideModeRequest(BaseModel):
    enabled: bool


# NEW
class DetectRequest(BaseModel):
    event: dict[str, Any]


# NEW
class ResponseTriggerRequest(BaseModel):
    threat: dict[str, Any]


# NEW
class ResponseRollbackRequest(BaseModel):
    action_id: str


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_LOG_QUERY_SYSTEM_PROMPT = (
    "You are a log filter interpreter for a cybersecurity system. \n"
    "Convert the user's natural language query into a JSON filter object.\n"
    "Return ONLY valid JSON with no explanation, no markdown, no backticks.\n\n"
    "JSON schema:\n"
    "{\n"
    "  'severity': 'high' | 'med' | 'low' | 'info' | null,\n"
    "  'tag': string | null,\n"
    "  'geo_country': string | null,\n"
    "  'time_window_minutes': integer | null,\n"
    "  'ip_contains': string | null,\n"
    "  'keyword': string | null\n"
    "}\n\n"
    "Examples:\n"
    "Query: 'failed logins from Russia in last 10 minutes'\n"
    "Response: {'severity':'high','geo_country':'Russia','time_window_minutes':10}\n\n"
    "Query: 'all port scans'\n"
    "Response: {'tag':'Port Scan'}\n\n"
    "Query: 'brute force attacks today'\n"
    "Response: {'tag':'Brute Force'}\n\n"
    "Query: 'high severity events'\n"
    "Response: {'severity':'high'}"
)

_log_filter_client = GeminiClient()


_ip_country_cache = {}

async def _resolve_country(ip: str) -> str:
    if ip in _ip_country_cache:
        return _ip_country_cache[ip]
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return "XX"
    try:
        # Prevent hanging ingest requests using 2s strict timeout
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode", timeout=2) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        country = str(data.get("countryCode", "XX")).upper()
                        _ip_country_cache[ip] = country
                        return country
    except Exception as e:
        print(f"⚠️ GeoIP fast-path failed for {ip}: {e}")
    _ip_country_cache[ip] = "XX"
    return "XX"

# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------

@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/api/events/history")
async def get_event_history(limit: int = 120) -> dict:
    """Return the most recent events from the database for dashboard preload."""
    from db.store import query_events
    events = query_events(limit=min(limit, 500))
    return {"status": "success", "data": events}


@router.post("/ingest")
async def ingest_event(event: Dict[str, Any]) -> dict:
    """
    Ingest a raw event from an external honeypot or web app directly into the SOC pipeline.
    The endpoint normalizes incoming JSON to match the pipeline's expected format.
    """
    print("🔥 RECEIVED EVENT:", event)
    
    timestamp = event.get("timestamp")
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
    elif not timestamp.endswith("Z") and "+" not in timestamp:
        timestamp = timestamp + "Z"
        
    status = "failure"
    if "success" in event:
        status = "success" if event["success"] else "failure"
    elif "status" in event:
        status = event.get("status", "failure")
        
    raw_event_type = event.get("event_type", "request")
    
    event_type = raw_event_type
    if "login" in raw_event_type.lower():
        event_type = "login"
    elif "request" in raw_event_type.lower() or "http" in raw_event_type.lower():
        event_type = "request"
    elif "connect" in raw_event_type.lower():
        event_type = "connection"

    source_ip = event.get("source_ip", "0.0.0.0")
    country = str(event.get("country", "")).upper()
    if not country or country == "XX":
        country = await _resolve_country(source_ip)

    normalized_event = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": event.get("destination_ip", "10.0.0.1"),
        "destination_port": int(event.get("destination_port", 443)),
        "protocol": event.get("protocol", "HTTP"),
        "event_type": event_type,
        "username": event.get("username", "unknown"),
        "status": status,
        "bytes_transferred": int(event.get("bytes_transferred", 500)),
        "country": country,
        "is_attack": event.get("is_attack", False),
        "is_ingested": True,
        "payload": str(event.get("endpoint", event.get("payload", "/")))
    }
    
    print("✅ NORMALIZED EVENT:", normalized_event)
    await event_stream_service.inject_event(normalized_event)
    
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Detection  (NEW)
# ---------------------------------------------------------------------------

@router.post("/api/detect")
async def detect_event(payload: DetectRequest) -> dict:
    """
    Run the full detection + intelligence pipeline on a single submitted event.

    Input:  { "event": { ...raw event fields... } }
    Output: enriched threat object including anomaly_score, risk_score, severity,
            attack_type, MITRE mapping, and score_breakdown.
    """
    if not payload.event:
        raise HTTPException(status_code=422, detail="event must not be empty")

    try:
        # 1. Anomaly detection (ML scoring)
        enriched = await asyncio.to_thread(detection_service.enrich_event, dict(payload.event))
        # 2. Intelligence enrichment (classification, risk score, MITRE, actor)
        threat = await asyncio.to_thread(intelligence_service.build_threat_object, enriched)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Detection failed: {exc}") from exc

    return {
        "status": "success",
        "data": {
            "anomaly_score": threat.get("anomaly_score"),
            "risk_score": threat.get("risk_score"),
            "severity": threat.get("severity"),
            "attack_type": threat.get("attack_type"),
            "mitre": threat.get("mitre"),
            "reason": threat.get("reason"),
            "score_breakdown": threat.get("score_breakdown", []),
            "threat": threat,
        },
    }


# ---------------------------------------------------------------------------
# NLP phishing
# ---------------------------------------------------------------------------

@router.post("/api/phishing/classify")
async def phishing_classify(payload: PhishingClassifyRequest) -> dict:
    """Run NLP phishing classification on an email subject + body."""
    result = await asyncio.to_thread(classify_email, payload.subject, payload.body)
    return {"status": "success", "data": result}


# ---------------------------------------------------------------------------
# Response  (NEW: trigger + rollback)
# ---------------------------------------------------------------------------

@router.post("/api/response/trigger")
async def response_trigger(payload: ResponseTriggerRequest) -> dict:
    """
    Manually trigger the response engine for a given threat dict.

    Input:  { "threat": { "source_ip": "...", "severity": "HIGH", ... } }
    Output: list of actions executed (or held pending approval).
    """
    if not payload.threat:
        raise HTTPException(status_code=422, detail="threat must not be empty")

    result = await asyncio.to_thread(response_service.handle_threat, dict(payload.threat))
    return {"status": "success", "data": result}


@router.post("/api/response/rollback")
async def response_rollback(payload: ResponseRollbackRequest) -> dict:
    """
    Roll back a previously executed action by its action_id.

    Input:  { "action_id": "act-7" }
    Output: rollback result (success / already_rolled_back / not_found).
    """
    if not payload.action_id:
        raise HTTPException(status_code=422, detail="action_id must not be empty")

    result = await asyncio.to_thread(response_service.rollback, payload.action_id)
    if result.get("rollback_status") == "failed" and result.get("reason") == "not_found":
        raise HTTPException(status_code=404, detail=f"action_id '{payload.action_id}' not found")

    return {"status": "success", "data": result}


# ---------------------------------------------------------------------------
# Operator control
# ---------------------------------------------------------------------------

@router.get("/api/threats/pending")
async def threats_pending() -> dict:
    """Return all threats currently awaiting human approval."""
    threats = await asyncio.to_thread(get_pending_threats)
    return {"status": "success", "data": threats, "count": len(threats)}


@router.get("/api/threats/active")
async def threats_active() -> dict:
    """
    Return the 20 most recent threats from persistent storage.
    Falls back to the in-memory operator store if the DB is empty.
    """
    db_threats = await asyncio.to_thread(query_threats, 20)
    if db_threats:
        return {"status": "success", "data": db_threats, "source": "db"}

    mem_threats = await asyncio.to_thread(get_all_threats)
    mem_sorted = sorted(mem_threats, key=lambda t: t.get("created_at", ""), reverse=True)
    return {"status": "success", "data": mem_sorted[:20], "source": "memory"}


@router.post("/api/threats/approve")
async def threats_approve(payload: ThreatDecisionRequest) -> dict:
    """Approve a PENDING threat — executes block_ip + create_ticket."""
    result = await asyncio.to_thread(approve_threat, payload.threat_id, payload.operator)
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result.get("reason", "unknown error"))
    return {"status": "success", "data": result}


@router.post("/api/threats/reject")
async def threats_reject(payload: ThreatDecisionRequest) -> dict:
    """Reject a PENDING threat — no actions executed."""
    result = await asyncio.to_thread(reject_threat, payload.threat_id, payload.operator)
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result.get("reason", "unknown error"))
    return {"status": "success", "data": result}


@router.post("/api/system/override")
async def system_override(payload: OverrideModeRequest) -> dict:
    """Enable or disable global override mode (suppresses all auto-responses)."""
    await asyncio.to_thread(set_override_mode, payload.enabled)
    return {
        "status": "success",
        "data": {
            "override_mode": payload.enabled,
            "message": (
                "All automated responses DISABLED — manual approval required."
                if payload.enabled
                else "Automated responses RE-ENABLED."
            ),
        },
    }


@router.get("/api/system/override")
async def system_override_status() -> dict:
    """Return current override mode status."""
    enabled = await asyncio.to_thread(get_override_mode)
    return {"status": "success", "data": {"override_mode": enabled}}


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@router.get("/api/audit/log")
async def audit_log_endpoint() -> dict:
    """
    Return the 50 most recent audit log entries from persistent storage.
    Falls back to in-memory when the DB has no entries yet.
    """
    db_log = await asyncio.to_thread(query_audit_log, 50)
    if db_log:
        return {"status": "success", "data": db_log, "count": len(db_log), "source": "db"}

    mem_log = await asyncio.to_thread(response_service.get_audit_log)
    recent = list(reversed(mem_log[-50:]))
    return {"status": "success", "data": recent, "count": len(recent), "source": "memory"}


# ---------------------------------------------------------------------------
# Attack simulation
# ---------------------------------------------------------------------------

@router.post("/api/simulate/attack")
async def simulate_attack(payload: AttackRequest) -> dict:
    result = await attack_controller.trigger_attack(
        payload.type,
        source_ip=str(payload.source_ip) if payload.source_ip is not None else None,
        target_ip=str(payload.target_ip) if payload.target_ip is not None else None,
    )
    return result


# ---------------------------------------------------------------------------
# Log query (NL → filter)
# ---------------------------------------------------------------------------

@router.post("/api/logs/query")
async def query_logs(payload: LogsQueryRequest) -> dict:
    # Always search full backend history (up to 4000 events) — never rely solely
    # on the frontend-sent slice which may not contain the matching events.
    backend_events = event_stream_service.get_recent_events(limit=4000)
    if payload.event_history:
        frontend_events = [dict(item) for item in payload.event_history if isinstance(item, dict)]
        # Merge: backend first (authoritative), then any frontend-only extras.
        seen_ts = {e.get("timestamp") for e in backend_events}
        extras = [e for e in frontend_events if e.get("timestamp") not in seen_ts]
        source_events = backend_events + extras
    else:
        source_events = backend_events

    try:
        model_prompt = f"{_LOG_QUERY_SYSTEM_PROMPT}\n\nQuery: '{payload.query}'"
        model_raw = await asyncio.to_thread(_log_filter_client.generate_analysis, model_prompt)
        interpreted_filter = await asyncio.to_thread(log_query_service.parse_model_response, model_raw)
    except Exception:
        interpreted_filter = await asyncio.to_thread(log_query_service.parse_query, payload.query)

    events = await asyncio.to_thread(
        log_query_service.apply_filter, source_events, interpreted_filter, 300
    )
    return {"query": payload.query, "filter": interpreted_filter, "events": events}


# ---------------------------------------------------------------------------
# AI Analyst reports
# ---------------------------------------------------------------------------

@router.post("/api/analyst/incident_report")
async def generate_incident_report(payload: ReportRequest) -> dict:
    recent_events = (
        [dict(item) for item in payload.events if isinstance(item, dict)]
        if payload.events
        else event_stream_service.get_recent_events(limit=500)
    )
    audit_actions = (
        [dict(item) for item in payload.actions if isinstance(item, dict)]
        if payload.actions
        else response_service.get_audit_log()
    )
    report = await analyst_service.generate_incident_report(
        {"events": recent_events[:500], "actions": audit_actions[:500]}
    )
    return {
        "status": "success",
        "data": {"generated_at": datetime.now(timezone.utc).isoformat(), "report": report},
    }


@router.post("/api/analyst/board_report")
async def generate_board_report(payload: ReportRequest) -> dict:
    recent_events = (
        [dict(item) for item in payload.events if isinstance(item, dict)]
        if payload.events
        else event_stream_service.get_recent_events(limit=500)
    )
    audit_actions = (
        [dict(item) for item in payload.actions if isinstance(item, dict)]
        if payload.actions
        else response_service.get_audit_log()
    )
    report = await analyst_service.generate_board_report(
        {"events": recent_events[:500], "actions": audit_actions[:500]}
    )
    return {
        "status": "success",
        "data": {"generated_at": datetime.now(timezone.utc).isoformat(), "report": report},
    }


@router.post("/api/analyst/persistence-insight")
async def generate_persistence_insight(payload: PersistenceInsightRequest) -> dict:
    threat = dict(payload.threat or {})
    threat.setdefault("source_ip", payload.source_ip)
    insight = await analyst_service.generate_persistence_insight(threat, payload.dwell_time)
    return {"status": "success", "data": {"insight": insight}}


@router.post("/api/analyst/query")
async def analyst_query(payload: AnalystQueryRequest) -> dict:
    analysis = await analyst_service.generate_manual_analysis(payload.threat, payload.query)
    return {"status": "success", "data": {"analysis": analysis}}


# ---------------------------------------------------------------------------
# SMS test endpoint
# ---------------------------------------------------------------------------

class TestSmsRequest(BaseModel):
    to: str | None = None


@router.post("/api/test/sms")
async def test_sms(payload: TestSmsRequest = TestSmsRequest()) -> dict:
    """
    Send a test SMS to verify Twilio configuration.

    Input:  { "to": "+1234567890" }  (optional — defaults to ADMIN_PHONE)
    Output: { "status": "sent"|"disabled"|"error", "message_sid": "...", "detail": "..." }
    """
    from notifications.sms import send_test_sms
    result = await asyncio.to_thread(send_test_sms, payload.to)
    return {"status": "success", "data": result}


# ---------------------------------------------------------------------------
# Operator / Human-in-the-Loop
# ---------------------------------------------------------------------------

class OverrideRequest(BaseModel):
    enabled: bool


class ThreatDecisionRequest(BaseModel):
    threat_id: str
    operator: str = "analyst"


@router.get("/api/operator/pending")
async def list_pending_threats() -> dict:
    """Return all threats currently awaiting human approval."""
    return {"status": "success", "data": get_pending_threats()}


@router.get("/api/operator/all")
async def list_all_operator_threats() -> dict:
    """Return all operator-tracked threats (PENDING + EXECUTED + REJECTED)."""
    return {"status": "success", "data": get_all_threats()}


@router.post("/api/operator/approve")
async def approve_pending_threat(payload: ThreatDecisionRequest) -> dict:
    """Approve a PENDING threat — executes queued response actions."""
    result = approve_threat(payload.threat_id, payload.operator)
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result.get("reason", "not_found"))
    return {"status": "success", "data": result}


@router.post("/api/operator/reject")
async def reject_pending_threat(payload: ThreatDecisionRequest) -> dict:
    """Reject a PENDING threat — no actions executed."""
    result = reject_threat(payload.threat_id, payload.operator)
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result.get("reason", "not_found"))
    return {"status": "success", "data": result}


@router.get("/api/operator/override")
async def get_override_status() -> dict:
    """Check whether global override mode is active."""
    return {"status": "success", "data": {"override_mode": get_override_mode()}}


@router.post("/api/operator/unblock")
async def unblock(data: dict):
    ip = data.get("ip")
    if ip:
        unblock_ip(ip)
    return {"status": "unblocked"}


@router.post("/api/operator/block")
async def manual_block(data: dict):
    ip = data.get("ip")
    if ip:
        block_ip(ip, trigger="Manual operator block")
    return {"status": "blocked"}


@router.get("/api/operator/blocked")
async def get_blocked_ips() -> dict:
    return {"status": "success", "data": list(blocked_ips)}


@router.post("/api/operator/override")
async def toggle_override(payload: OverrideRequest) -> dict:
    """Enable or disable global override mode (suppresses all auto-responses)."""
    set_override_mode(payload.enabled)
    return {"status": "success", "data": {"override_mode": payload.enabled}}


# ---------------------------------------------------------------------------
# Legacy aliases (kept for backwards compatibility)
# ---------------------------------------------------------------------------

@router.post("/api/report/incident")
async def generate_incident_report_legacy(payload: ReportRequest) -> dict:
    return await generate_incident_report(payload)


@router.post("/api/report/board")
async def generate_board_report_legacy(payload: ReportRequest) -> dict:
    return await generate_board_report(payload)
