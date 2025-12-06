from __future__ import annotations

from typing import Optional


class RoutingTable:
    """
    Very simple routing abstraction.

    For now:
    - We only support direct neighbors (single hop).
    - If destination_id is in peers_by_id, we return that peer as the next hop.
    - Otherwise, we return None (no route).
    """

    def __init__(self, self_id: str, peers_by_id: dict[str, dict]):
        self.self_id = self_id
        self.peers_by_id = peers_by_id

    def get_next_hop(self, destination_id: str) -> Optional[dict]:
        """
        Return the peer dict to which we should send the packet
        in order to reach destination_id.

        For now: direct routing only.
        """
        if destination_id == self.self_id:
            # We're the destination; no next hop needed.
            return None

        # Direct neighbor?
        return self.peers_by_id.get(destination_id)
