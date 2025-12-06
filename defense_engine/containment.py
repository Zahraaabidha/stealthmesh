from __future__ import annotations


from collections import defaultdict
from typing import Dict, Any, Set, Callable, Optional

from .firewall_adapter import FirewallAdapter

class ContainmentEngine:
    """
    Decides how to react to alerts and what to do with traffic
    from suspicious nodes.

    We simulate three actions:
      - "allow": process normally
      - "block": drop traffic (micro-quarantine)
      - "decoy": divert to decoy service instead of real logic

    It also tracks collaborative evidence:
    if enough different nodes raise ALERTs about the same suspect,
    we escalate to network-wide quarantine.
    """

    def __init__(self, node_id: str, quarantine_threshold_sources: int = 2, on_action: Optional[Callable[[dict], None]] = None,):
        self.node_id = node_id
        # How many distinct alert sources required to escalate network-wide.
        self.quarantine_threshold_sources = quarantine_threshold_sources

        # suspect_id -> set of node_ids that raised alerts about it
        self.alert_sources: Dict[str, Set[str]] = defaultdict(set)

        # Current containment decisions
        self.blocked_suspects: Set[str] = set()
        self.decoy_suspects: Set[str] = set()

        # Optional callback to send ACTION events (e.g., to dashboard)
        self.on_action = on_action

        self.firewall = FirewallAdapter(rule_prefix=f"StealthMesh_{node_id}")



    # ---------- Policy query ----------

    def get_action_for_suspect(self, suspect_id: str) -> str:
        """
        Return "allow", "block", or "decoy" for this suspect.
        """
        if suspect_id in self.decoy_suspects:
            return "decoy"
        if suspect_id in self.blocked_suspects:
            return "block"
        return "allow"

    # ---------- Alert handling ----------

    def handle_local_alert(self, alert: Dict[str, Any]) -> None:
        """
        Called when THIS node's DetectionEngine raises an alert.
        We treat local alerts as strong evidence and may quarantine immediately.
        """
        suspect = alert.get("suspect")
        source = alert.get("source") or self.node_id
        if not suspect:
            return

        self.alert_sources[suspect].add(source)

        extra = alert.get("extra", {}) or {}
        alert_type = extra.get("type")  # e.g. FAILED_LOGIN_BURST, PORT_SCAN
        confidence = float(alert.get("confidence", 0.0))

        # Simple policy:
        # - FAILED_LOGIN_BURST or PORT_SCAN with high confidence => local quarantine
        if alert_type in {"FAILED_LOGIN_BURST", "PORT_SCAN"} and confidence >= 0.7:
            if suspect not in self.decoy_suspects:
                self.decoy_suspects.add(suspect)
                print(
                    f"[{self.node_id}/Containment] Diverting suspect={suspect} to DECOY"
                    f"for alert_type={alert_type}, confidence={confidence}"
                )
            # Send ACTION event (optional)
                if self.on_action:
                    self.on_action({
                        "type": "ACTION",
                        "node_id": self.node_id,
                        "data": {
                            "action": "DIVERT_TO_DECOY",
                            "target": suspect,
                            "details": {
                                "alert_type": alert_type,
                                "confidence": confidence,
                            },
                        },
                    })
    

    def handle_peer_alert(self, alert: Dict[str, Any]) -> None:
        """
        Called when this node receives an ALERT message from another node.

        We aggregate sources: if enough DIFFERENT nodes raise alerts
        about the same suspect, we escalate to network-wide quarantine.
        """
        suspect = alert.get("suspect")
        source = alert.get("source")
        if not suspect or not source:
            return

        sources = self.alert_sources[suspect]
        sources.add(source)

        if (
            len(sources) >= self.quarantine_threshold_sources
            and suspect not in self.blocked_suspects
        ):
            # Network-wide hard quarantine
            self.blocked_suspects.add(suspect)
                        # Example: treat suspect as IP and block it (if it's an IP)
            if suspect and suspect[0].isdigit():  # very naive check
                self.firewall.block_ip(suspect)

            # Optional: once fully blocked, we can remove from decoy
            if suspect in self.decoy_suspects:
                self.decoy_suspects.remove(suspect)

            print(
                f"[{self.node_id}/Containment] Network-wide quarantine for suspect={suspect} "
                f"(alert_sources={sorted(sources)})"
            )

            if self.on_action:
                self.on_action({
                    "type": "ACTION",
                    "node_id": self.node_id,
                    "data": {
                        "action": "NETWORK_QUARANTINE",
                        "target": suspect,
                        "details": {
                            "alert_sources": sorted(sources),
                        },
                    },
                })
