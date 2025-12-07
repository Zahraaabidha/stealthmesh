from __future__ import annotations

import requests  # for HTTP calls to dashboard
import argparse
import json
import socket
import threading
import time
import random
from pathlib import Path

import yaml

from defense_engine.alert_protocol import AlertProtocol
from defense_engine.detection import DetectionEngine
from defense_engine.containment import ContainmentEngine
from defense_engine.deception import DeceptionEngine
from .crypto_utils import load_key, encrypt_symmetric, decrypt_symmetric
from .routing import RoutingTable 
from .stealth_layer import StealthLayer

class NodeAgent:
    """
    Represents a single StealthMesh node.

    - Loads configuration from YAML.
    - Holds network + crypto settings.
    - Can start a TCP server and send encrypted messages to peers.
    """

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        config_dict = self._load_config()

        # Basic config
        self.node_id: str = config_dict["node_id"]
        self.listen_host: str = config_dict["listen_host"]
        self.listen_port: int = config_dict["listen_port"]
        self.peers: list[dict] = config_dict.get("peers", [])
        self.key_paths: dict = config_dict.get("keys", {})

        # Map peers by node_id for convenience
        self.peers_by_id: dict[str, dict] = {
            peer["node_id"]: peer for peer in self.peers
        }
        self.routing = RoutingTable(self.node_id, self.peers_by_id)

        # Load (or create) symmetric key from private_key_path
        private_key_path = self.key_paths.get("private_key_path")
        if not private_key_path:
            raise ValueError("keys.private_key_path is required in config")

        self.root_key: bytes = load_key(private_key_path)
        self.stealth = StealthLayer(
            self.node_id, 
            root_key=self.root_key,
            min_pad=0,
            max_pad=64,
            rotation_interval_sec=300,)
        
                # Dashboard backend URL (can later move to config/env)
        self.dashboard_url: str | None = "https://stealthmesh-backend.onrender.com/events"

        
                # Defense engine: detection + alerts
        self.alert_protocol = AlertProtocol(
            node_id=self.node_id,
            on_emit=self._handle_alert,   # callback into NodeAgent
        )
        self.detection = DetectionEngine(
            node_id=self.node_id,
            alert_protocol=self.alert_protocol,
        )

                # Containment + deception
        # You can tune quarantine_threshold_sources; with 2+ nodes, 2 is a good demo.
        self.containment = ContainmentEngine(
            node_id=self.node_id,
            quarantine_threshold_sources=2,
            on_action=self._send_event_to_dashboard,
        )
        self.deception = DeceptionEngine(self.node_id)



    def _load_config(self) -> dict:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        with self.config_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Config file {self.config_path} did not contain a YAML object")

        return data

    # ------------- Networking -------------

    def start_server(self) -> None:
        """
        Start a simple TCP server that:
        - listens on (listen_host, listen_port)
        - accepts connections
        - decrypts incoming message
        - prints JSON message content
        """
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.listen_host, self.listen_port))
        server_sock.listen()

        print(f"[{self.node_id}] Listening on {self.listen_host}:{self.listen_port}")


        def handle_client(conn: socket.socket, addr):
            try:
                data = conn.recv(4096)
                if not data:
                    return

                message = self.stealth.decrypt_incoming(data)
                msg_type = message.get("type")
                suspect_id = message.get("from") or f"{addr[0]}:{addr[1]}"

                # Step 1: Containment check (but always allow ALERTs through)
                action = self.containment.get_action_for_suspect(suspect_id)

                if msg_type != "ALERT":
                    if action == "block":
                        print(
                            f"[{self.node_id}/Containment] BLOCKED message from suspect={suspect_id} "
                            f"at {addr} msg_type={msg_type}"
                        )
                        return

                    if action == "decoy":
                        # Divert to decoy instead of normal processing
                        self.deception.handle_decoy_request(suspect_id, message, addr,)
                        return

                # Step 2: Normal handling
                if msg_type == "ALERT":
                    # Alerts coming from other nodes
                    print(f"[{self.node_id}] Received ALERT from peer: {message}")
                    # Update containment with peer evidence
                    self.containment.handle_peer_alert(message)
                else:
                    # Normal messages go through detection engine
                    print(f"[{self.node_id}] Received from {addr}: {message}")
                    self.detection.handle_message(message, addr)

            except Exception as e:
                print(f"[{self.node_id}] Error handling client {addr}: {e}")
            finally:
                conn.close()

        # Main accept loop (runs in its own thread)
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


    def send_message(self, destination_id: str, message_dict: dict) -> None:
        """
        Send a message towards destination_id using the routing layer.

        For now, this is just direct neighbor routing.
        """
        next_hop = self.routing.get_next_hop(destination_id)
        if next_hop is None:
            raise ValueError(f"No route to destination_id={destination_id}")

        host = next_hop["host"]
        port = next_hop["port"]

        time.sleep(random.uniform(0.01, 0.2))

        ciphertext = self.stealth.encrypt_outgoing(message_dict)

        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(ciphertext)
    

        print(f"[{self.node_id}] Sent message towards {destination_id} "
              f"via next hop {next_hop['node_id']} at {host}:{port}")
    

    def send_ping(self, target_node_id: str) -> None:
        """
        Convenience helper to send a PING message.
        """
        message = {
            "type": "PING",
            "from": self.node_id,
            "payload": "hello",
            "timestamp": time.time(),
        }
        self.send_message(target_node_id, message)

    def send_auth_fail_burst(self, target_node_id: str, count: int = 10) -> None:
        """
        Simulate a burst of failed login attempts against a peer.

        This sends `count` messages of type AUTH_FAIL to target_node_id.
        DetectionEngine will treat these as failed logins from self.node_id.
        """
        for i in range(count):
            message = {
                "type": "AUTH_FAIL",
                "from": self.node_id,
                "payload": {
                    "attempt": i + 1,
                    "method": "SSH",  # or "HTTP" etc.
                },
                "timestamp": time.time(),
            }
            self.send_message(target_node_id, message)

    def send_port_probe_sweep(
        self,
        target_node_id: str,
        start_port: int = 10000,
        count: int = 20,
    ) -> None:
        """
        Simulate a port scan against a peer by sending PORT_PROBE messages
        for a sequence of ports.

        DetectionEngine will treat these as port probes from self.node_id.
        """
        for i in range(count):
            port = start_port + i
            message = {
                "type": "PORT_PROBE",
                "from": self.node_id,
                "port": port,
                "timestamp": time.time(),
            }
            self.send_message(target_node_id, message)

    def _send_event_to_dashboard(self, event: dict) -> None:
        """
        Best-effort: send an event to the dashboard backend.

        If the dashboard is down or unreachable, we just log and continue.
        """
        if not self.dashboard_url:
            return

        try:
            requests.post(self.dashboard_url, json=event, timeout=3)
        except Exception as e:
            print(f"[{self.node_id}/Dashboard] Failed to send event: {e}")


    def push_status_loop(self, interval=10):
        """Periodically send node status to dashboard."""
        while True:
           event = {
            "type": "STATUS",
            "node_id": self.node_id,
            "timestamp": time.time(),
            "data": {
                "peers": list(self.peers_by_id.keys()),
                "port": self.listen_port
            }
        }
        self._send_event_to_dashboard(event)
        time.sleep(interval)
       



    def _handle_alert(self, alert: dict) -> None:
        """
        Called by AlertProtocol when THIS node raises a local alert.

        We:
        - log it locally
        - pass it to containment engine
        - broadcast to all peers
        - send an ALERT event to dashboard
        """
        print(f"[{self.node_id}][ALERT][LOCAL] {alert}")

        # Update local containment decisions
        self.containment.handle_local_alert(alert)

        # Send alert event to dashboard
        event = {
            "type": "ALERT",
            "node_id": self.node_id,
            "timestamp": alert.get("timestamp"),
            "data": {
                "suspect": alert.get("suspect"),
                "reason": alert.get("reason"),
                "confidence": alert.get("confidence", 0.0),
                "extra": alert.get("extra", {}),
            },
        }
        self._send_event_to_dashboard(event)

        # Inform peers
        self.broadcast_alert(alert)

    def broadcast_alert(self, alert: dict) -> None:
        """
        Send an ALERT message to all peers.
        """
        for peer_id in self.peers_by_id.keys():
            try:
                if peer_id == self.node_id:
                    continue
                self.send_message(peer_id, alert)
            except Exception as e:
                print(f"[{self.node_id}] Error broadcasting alert to {peer_id}: {e}")


    def cover_traffic_loop(self, interval_sec: float = 5.0) -> None:
        """
        Periodically send COVER (decoy) messages to random peers.

        This creates background noise so that real traffic is harder to distinguish.
        """
        while True:
            try:
                if not self.peers_by_id:
                    time.sleep(interval_sec)
                    continue

                target_id = random.choice(list(self.peers_by_id.keys()))
                cover_message = {
                    "type": "COVER",
                    "from": self.node_id,
                    "payload": "noise",
                    "timestamp": time.time(),
                }
                self.send_message(target_id, cover_message)
            except Exception as e:
                print(f"[{self.node_id}] Error in cover_traffic_loop: {e}")

            time.sleep(interval_sec)

    def key_rotation_loop(self, interval_sec: float = 300.0) -> None:
        """
        Background loop that periodically triggers StealthLayer.rotate_keys().

        Currently rotate_keys is a stub; later you can implement true polymorphism.
        """
        while True:
            try:
                self.stealth.rotate_keys()
            except Exception as e:
                print(f"[{self.node_id}] Error in key_rotation_loop: {e}")

            time.sleep(interval_sec)


# ------------- CLI entrypoint -------------

def main() -> None:
    parser = argparse.ArgumentParser(description="StealthMesh NodeAgent")
    parser.add_argument("node_id", help="ID of this node (should match config.node_id)")
    parser.add_argument("config_path", help="Path to YAML config for this node")
    parser.add_argument(
        "--send-ping-to",
        dest="send_ping_to",
        help="If provided, send a PING to the given peer node_id after startup",
    )

    parser.add_argument(
        "--auth-fail-to",
        dest="auth_fail_to",
        help="If provided, send a burst of AUTH_FAIL messages to the given peer node_id",
    )
    parser.add_argument(
        "--auth-fail-count",
        dest="auth_fail_count",
        type=int,
        default=10,
        help="Number of AUTH_FAIL messages to send in the burst (default: 10)",
    )

    parser.add_argument(
        "--port-scan-to",
        dest="port_scan_to",
        help="If provided, send a PORT_PROBE sweep to the given peer node_id",
    )
    parser.add_argument(
        "--port-scan-count",
        dest="port_scan_count",
        type=int,
        default=20,
        help="Number of ports to probe in the sweep (default: 20)",
    )
    parser.add_argument(
        "--port-scan-start-port",
        dest="port_scan_start_port",
        type=int,
        default=10000,
        help="Starting port number for the sweep (default: 10000)",
    )



    args = parser.parse_args()

    agent = NodeAgent(args.config_path)

    if agent.node_id != args.node_id:
        print(f"[WARN] node_id argument ({args.node_id}) != config.node_id ({agent.node_id})")

    # Start server in background thread
    server_thread = threading.Thread(target=agent.start_server, daemon=True)
    server_thread.start()

    key_thread = threading.Thread(
        target=agent.key_rotation_loop,
        kwargs={"interval_sec": 300.0},  # every 5 minutes; you can lower for testing
        daemon=True,
    )
    key_thread.start()

    # Start cover traffic loop
    cover_thread = threading.Thread(
        target=agent.cover_traffic_loop,
        kwargs={"interval_sec": 300.0},  # send cover traffic every 5 seconds
        daemon=True,
    )
    cover_thread.start()

    
    # Start periodic status updates to dashboard
    status_thread = threading.Thread(
    target=agent.push_status_loop,
    daemon=True
)
    status_thread.start()


    # Optional: send one PING if requested
    if args.send_ping_to:
        # small delay so the other node has time to start listening
        time.sleep(1.0)
        agent.send_ping(args.send_ping_to)

        # Optional: send a burst of AUTH_FAIL messages (simulated brute-force)
    if args.auth_fail_to:
        # small delay so the other node has time to start listening
        time.sleep(1.0)
        agent.send_auth_fail_burst(args.auth_fail_to, args.auth_fail_count)

    if args.port_scan_to:
        time.sleep(1.0)
        agent.send_port_probe_sweep(
            args.port_scan_to,
            start_port=args.port_scan_start_port,
            count=args.port_scan_count,
        )
    


    # Keep main thread alive
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print(f"[{agent.node_id}] Shutting down.")


if __name__ == "__main__":
    # IMPORTANT: run this via `python -m mesh_core.node_agent ...`
    main()
