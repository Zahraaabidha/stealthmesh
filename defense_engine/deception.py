from __future__ import annotations

from typing import Optional, Dict, Any
import requests


class DeceptionEngine:
    """
    Handles decoy / honeypot behaviour.

    When containment decides that a suspect's traffic should be diverted
    to a decoy, NodeAgent calls handle_decoy(...), which:
    - logs locally
    - (optionally) forwards the event to an external decoy HTTP service
    """

    def __init__(
        self,
        node_id: str,
        decoy_url: Optional[str] = "http://127.0.0.1:9005/decoy",
    ):
        self.node_id = node_id
        # If decoy_url is None, we only log locally and do not send HTTP.
        self.decoy_url = decoy_url

    # --- internal helper -------------------------------------------------

    def _send_to_decoy_service(
        self,
        suspect_id: str,
        msg_type: str,
        message: Dict[str, Any],
        addr,
    ) -> None:
        """Send a JSON event to the external decoy HTTP service."""
        if not self.decoy_url:
            return

        try:
            requests.post(
                self.decoy_url,
                json={
                    "node_id": self.node_id,
                    "suspect": suspect_id,
                    "msg_type": msg_type,
                    "message": message,
                },
                timeout=1.0,
            )
        except Exception as e:
            print(f"[{self.node_id}/DECOY] Failed to send to decoy service: {e}")

    # --- public entrypoints ----------------------------------------------

    def handle_decoy(self, suspect_id: str, message: Dict[str, Any], addr) -> None:
        """
        Main API: called by NodeAgent when a message from `suspect_id`
        should be handled as decoy traffic.
        """
        msg_type = message.get("type")

        # Local log: this is what you've already been seeing.
        print(
            f"[{self.node_id}/DECOY] Diverted message from suspect={suspect_id} "
            f"at {addr} msg_type={msg_type} message={message}"
        )

        # Optionally forward to external decoy service
        self._send_to_decoy_service(
            suspect_id=suspect_id,
            msg_type=msg_type,
            message=message,
            addr=addr,
        )

    def handle_decoy_request(self, suspect_id: str, message: Dict[str, Any], addr) -> None:
        """
        Backwards-compatible alias. If any existing code calls
        handle_decoy_request(...), it simply forwards to handle_decoy(...).
        """
        self.handle_decoy(suspect_id, message, addr)
