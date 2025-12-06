from __future__ import annotations


from datetime import datetime
from typing import List, Literal, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# ----------------- Data models -----------------


class EventIn(BaseModel):
    """
    Generic event schema sent by NodeAgents.

    type:
      - "STATUS": node status update
      - "ALERT": alert raised by a node
      - "ACTION": containment / deception action
    """
    type: Literal["STATUS", "ALERT", "ACTION"]
    node_id: str
    timestamp: Optional[float] = None  # Unix time, optional; backend will fill if missing
    # free-form payload
    data: dict


class NodeStatus(BaseModel):
    node_id: str
    last_seen: float
    state: Literal["NORMAL", "UNDER_ATTACK", "QUARANTINE", "UNKNOWN"]


class AlertOut(BaseModel):
    node_id: str          # source node that raised the alert
    timestamp: float
    suspect: str
    reason: str
    confidence: float
    extra: dict


class ActionOut(BaseModel):
    node_id: str
    timestamp: float
    action: str
    target: Optional[str] = None
    details: dict


# ----------------- In-memory stores -----------------

# node_id -> NodeStatus
NODES: dict[str, NodeStatus] = {}

# recent alerts (append-only list)
ALERTS: List[AlertOut] = []

# recent actions (append-only list)
ACTIONS: List[ActionOut] = []


# ----------------- FastAPI app -----------------


app = FastAPI(title="StealthMesh Dashboard Backend")

# Add this block:
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow all origins (fine for local demo)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------- helper functions ----------------

def _now_ts() -> float:
    return datetime.utcnow().timestamp()


def _update_node_status_from_event(event: EventIn) -> None:
    ts = event.timestamp or _now_ts()
    status = NODES.get(event.node_id) or NodeStatus(
        node_id=event.node_id,
        last_seen=ts,
        state="UNKNOWN",
    )
    status.last_seen = ts

    # Optional: allow state in data, else keep previous
    new_state = event.data.get("state")
    if isinstance(new_state, str) and new_state in {"NORMAL", "UNDER_ATTACK", "QUARANTINE"}:
        status.state = new_state
    else:
        # If not explicitly set, assume NORMAL unless we already know better
        if status.state == "UNKNOWN":
            status.state = "NORMAL"

    NODES[event.node_id] = status


def _handle_alert_event(event: EventIn) -> None:
    ts = event.timestamp or _now_ts()
    data = event.data
    suspect = data.get("suspect", "unknown")
    reason = data.get("reason", "unspecified")
    confidence = float(data.get("confidence", 0.0))
    extra = data.get("extra") or {}

    alert = AlertOut(
        node_id=event.node_id,
        timestamp=ts,
        suspect=suspect,
        reason=reason,
        confidence=confidence,
        extra=extra,
    )
    ALERTS.append(alert)

    # Mark node as UNDER_ATTACK if it raises an alert
    status = NODES.get(event.node_id)
    if status:
        status.state = "UNDER_ATTACK"
        status.last_seen = ts
        NODES[event.node_id] = status
    else:
        NODES[event.node_id] = NodeStatus(
            node_id=event.node_id,
            last_seen=ts,
            state="UNDER_ATTACK",
        )


def _handle_action_event(event: EventIn) -> None:
    ts = event.timestamp or _now_ts()
    data = event.data
    action = data.get("action", "UNKNOWN_ACTION")
    target = data.get("target")
    details = data.get("details") or {}

    act = ActionOut(
        node_id=event.node_id,
        timestamp=ts,
        action=action,
        target=target,
        details=details,
    )
    ACTIONS.append(act)

    # If this is a quarantine/decoy action, we can also update node state
    if action in {"DIVERT_TO_DECOY", "NETWORK_QUARANTINE"}:
        status = NODES.get(event.node_id)
        if status:
            status.state = "QUARANTINE"
            status.last_seen = ts
            NODES[event.node_id] = status


# ----------------- API endpoints -----------------


@app.post("/events")
def ingest_event(event: EventIn):
    """
    Main ingestion endpoint for NodeAgents.

    They POST:
      - STATUS events (node state updates)
      - ALERT events (detection alerts)
      - ACTION events (containment/deception)
    """

    if event.timestamp is None:
        event.timestamp = _now_ts()

    # Update node presence for all events
    _update_node_status_from_event(event)

    if event.type == "ALERT":
        _handle_alert_event(event)
    elif event.type == "ACTION":
        _handle_action_event(event)
    # STATUS events are already handled by _update_node_status_from_event

    return {"ok": True}


@app.get("/nodes", response_model=List[NodeStatus])
def list_nodes():
    """
    List all nodes and their last known status.
    """
    return list(NODES.values())


@app.get("/alerts", response_model=List[AlertOut])
def list_alerts(limit: int = 100):
    """
    Return recent alerts (most recent last).
    """
    if limit <= 0:
        return []
    return ALERTS[-limit:]


@app.get("/actions", response_model=List[ActionOut])
def list_actions(limit: int = 100):
    """
    Return recent containment/deception actions.
    """
    if limit <= 0:
        return []
    return ACTIONS[-limit:]
