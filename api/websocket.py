from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from analyst.service import analyst_service
from detection.service import detection_service
from intelligence.service import intelligence_service
from response.service import response_service
from simulator.generator import EventSimulator, event_stream_service

router = APIRouter()


# ---------------------------------------------------------------------------
# Analyst streaming WebSocket
# ---------------------------------------------------------------------------

@router.websocket("/api/analyst/stream")
async def analyst_stream(websocket: WebSocket) -> None:
    """
    Stream analyst analysis word-by-word for a typing effect.

    Client sends one JSON message:
        { "query": "...", "threat": { ...optional threat context... } }

    Server replies with a sequence of:
        { "type": "analysis_stream", "chunk": "<word> " }
    followed by:
        { "type": "analysis_stream_end" }

    On error the server sends:
        { "type": "analysis_stream_error", "detail": "..." }
    then closes.
    """
    await websocket.accept()

    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
    except (asyncio.TimeoutError, WebSocketDisconnect):
        return

    try:
        import json as _json
        data = _json.loads(raw)
    except Exception:
        await websocket.send_json({"type": "analysis_stream_error", "detail": "invalid_json"})
        await websocket.close()
        return

    query: str = str(data.get("query", "")).strip()
    threat: dict = data.get("threat") or {}

    if not query:
        await websocket.send_json({"type": "analysis_stream_error", "detail": "query_required"})
        await websocket.close()
        return

    try:
        analysis: str = await analyst_service.generate_manual_analysis(threat or None, query)
    except Exception as exc:
        await websocket.send_json({"type": "analysis_stream_error", "detail": str(exc)})
        await websocket.close()
        return

    # Stream word-by-word with a small delay for typing effect.
    words = analysis.split()
    try:
        for i, word in enumerate(words):
            # Add space after every word except the last.
            chunk = word + (" " if i < len(words) - 1 else "")
            await websocket.send_json({"type": "analysis_stream", "chunk": chunk})
            await asyncio.sleep(0.03)
        await websocket.send_json({"type": "analysis_stream_end"})
    except WebSocketDisconnect:
        pass
    except Exception:
        # Client disconnected mid-stream — not an error.
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@router.websocket("/api/events/stream")
async def stream_events(websocket: WebSocket) -> None:
    await websocket.accept()
    attack_mode = websocket.query_params.get("attack", "mixed").lower()
    send_interval_seconds = 0.5

    if attack_mode in {"bruteforce", "portscan"}:
        await _stream_attack_mode(websocket, attack_mode, target_eps=3)
        return

    queue = await event_stream_service.subscribe()

    try:
        while True:
            latest_event = await queue.get()
            drained_events = [latest_event]
            while True:
                try:
                    latest_event = queue.get_nowait()
                    drained_events.append(latest_event)
                except asyncio.QueueEmpty:
                    break

            response_events = [
                event for event in drained_events if str(event.get("type", "")) == "response_fired"
            ]
            for response_event in response_events:
                await websocket.send_json(response_event)

            coordinated_events = [
                event
                for event in drained_events
                if str(event.get("type", "")) == "campaign_detected"
            ]
            for coordinated_event in coordinated_events:
                await websocket.send_json(coordinated_event)

            threat_events = [
                event
                for event in drained_events
                if str(event.get("type", "")) not in {"response_fired", "campaign_detected"}
            ]
            if not threat_events:
                await asyncio.sleep(send_interval_seconds)
                continue

            prioritized = next(
                (
                    event
                    for event in reversed(threat_events)
                    if str(event.get("attack_type", "NORMAL")) != "NORMAL"
                    or bool(event.get("actions"))
                    or str(event.get("severity", "LOW")) in {"HIGH", "CRITICAL"}
                ),
                threat_events[-1],
            )

            await websocket.send_json(_safe_payload(prioritized))
            await asyncio.sleep(send_interval_seconds)

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        await websocket.send_json(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "attack_type": "SYSTEM",
                "severity": "LOW",
                "risk_score": 0,
                "reason": "Data temporarily unavailable",
                "analysis": f"stream_error: {exc}",
                "actions": [],
            }
        )
    finally:
        await event_stream_service.unsubscribe(queue)


async def _stream_attack_mode(websocket: WebSocket, attack_mode: str, target_eps: int = 12) -> None:
    simulator = EventSimulator(attack_ratio=1.0)
    interval = 1.0 / max(target_eps, 1)
    next_tick = time.perf_counter()

    try:
        while True:
            event = await asyncio.to_thread(simulator.generate_event, attack_mode=attack_mode)
            await asyncio.to_thread(event_stream_service.update_dwell_tracker, event)
            event = await asyncio.to_thread(detection_service.enrich_event, event)
            threat = await asyncio.to_thread(intelligence_service.build_threat_object, event)
            threat = await asyncio.to_thread(event_stream_service.attach_dwell_fields, threat)
            await asyncio.to_thread(event_stream_service.record_live_context, threat)
            threat["live_context"] = await asyncio.to_thread(event_stream_service.snapshot_live_context)
            threat = await analyst_service.enrich_threat(threat)
            response = await asyncio.to_thread(response_service.handle_threat, threat)
            threat["actions"] = response["actions_executed"]
            counterfactual_trigger = next(
                (
                    action.get("counterfactual_trigger")
                    for action in threat["actions"]
                    if isinstance(action, dict)
                    and isinstance(action.get("counterfactual_trigger"), dict)
                ),
                None,
            )
            if counterfactual_trigger:
                counterfactual_threat = {
                    **threat,
                    "attack_type": str(counterfactual_trigger.get("attack_type", threat.get("attack_type", "UNKNOWN"))),
                    "risk_score": int(counterfactual_trigger.get("risk_score", threat.get("risk_score", 0)) or 0),
                    "destination_ip": str(counterfactual_trigger.get("target_asset", threat.get("destination_ip", "unknown"))).split(":")[0],
                }
                threat["counterfactual"] = {
                    "title": "⚡ If SENTINEL hadn't responded...",
                    "text": await analyst_service.generate_counterfactual(
                        counterfactual_threat,
                        str(counterfactual_trigger.get("ip", threat.get("source_ip", "unknown"))),
                    ),
                    "badge": "simulated",
                }
            await websocket.send_json(_safe_payload(threat))
            response_payload = await _response_fired_payload(threat, threat["actions"])
            if response_payload:
                await websocket.send_json(response_payload)

            next_tick += interval
            delay = next_tick - time.perf_counter()
            if delay > 0:
                await asyncio.sleep(delay)
            elif delay < -1.0:
                next_tick = time.perf_counter()

    except WebSocketDisconnect:
        return
    except Exception as exc:
        await websocket.send_json(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "attack_type": "SYSTEM",
                "severity": "LOW",
                "risk_score": 0,
                "reason": "Data temporarily unavailable",
                "analysis": f"stream_error: {exc}",
                "actions": [],
            }
        )


def _safe_payload(event: dict) -> dict:
    payload = dict(event or {})
    payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    payload.setdefault("source_ip", "unknown")
    payload.setdefault("event_type", "connection")
    payload.setdefault("status", "failure")
    payload.setdefault("attack_type", "NORMAL")
    payload.setdefault("anomaly_score", 0.0)
    payload.setdefault("risk_score", 0)
    payload.setdefault("severity", "LOW")
    payload.setdefault("score_breakdown", [])
    payload.setdefault("mitre", {"technique": "N/A", "tactic": "None"})
    payload.setdefault("reason", "No suspicious behavior detected")
    payload.setdefault("analysis", "Automated analysis unavailable. Likely attack detected. Recommend blocking source and investigating.")
    payload.setdefault("dwell_seconds", 0)
    payload.setdefault("event_count", 0)
    payload.setdefault("is_persistent", False)
    payload.setdefault("actions", [])
    return payload


def _format_response_action_line(action: dict) -> str | None:
    status = str(action.get("status", "")).lower()
    if status != "success":
        return None

    action_name = str(action.get("action", "")).strip().lower()
    target = str(action.get("target", "unknown")).strip() or "unknown"

    if action_name == "block_ip":
        return f"IP {target} blocked"
    if action_name == "lock_account":
        return f"Account {target} locked 30min"
    if action_name in {"create_ticket", "create_alert"}:
        ticket_id = target.replace("act-", "")
        return f"Ticket #{ticket_id} created"
    return None


async def _response_fired_payload(threat: dict, actions: list[dict]) -> dict | None:
    # Group actions from the same playbook execution into one toast payload.
    await asyncio.sleep(0.5)
    action_lines = [line for line in (_format_response_action_line(action) for action in actions) if line]
    if not action_lines:
        return None

    return {
        "type": "response_fired",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": str(threat.get("source_ip", "unknown")),
        "attack_type": str(threat.get("attack_type", "UNKNOWN")),
        "severity": str(threat.get("severity", "LOW")),
        "actions": action_lines,
        "counterfactual": threat.get("counterfactual"),
    }
