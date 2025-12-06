from __future__ import annotations

import time
from typing import Callable, Dict, Any


class AlertProtocol:
    """
    Responsible for constructing and emitting ALERT messages.

    It does NOT send over the network by itself – instead, it calls
    the `on_emit` callback provided by NodeAgent.
    """

    def __init__(self, node_id: str, on_emit: Callable[[Dict[str, Any]], None]):
        self.node_id = node_id
        self.on_emit = on_emit

    def build_alert(
        self,
        suspect: str,
        reason: str,
        confidence: float,
        extra: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """
        Create an ALERT message dict following the mesh protocol shape.
        """
        alert = {
            "type": "ALERT",
            "source": self.node_id,        # the node raising the alert
            "suspect": suspect,            # IP, node_id, etc.
            "reason": reason,              # human-readable reason
            "confidence": float(confidence),
            "timestamp": time.time(),
        }
        if extra:
            alert["extra"] = extra
        return alert

    def emit_alert(
        self,
        suspect: str,
        reason: str,
        confidence: float,
        extra: Dict[str, Any] | None = None,
    ) -> None:
        """
        Build an alert and pass it to NodeAgent via the callback.
        """
        alert = self.build_alert(suspect, reason, confidence, extra=extra)
        self.on_emit(alert)
