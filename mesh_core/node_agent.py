from __future__ import annotations

import requests  # for HTTP calls to dashboard
import argparse
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
from .crypto_utils import load_key
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

        # Load symmetric key
        private_key_path = self.key_paths.get("private_key_path")
        if not private_key_path:
            raise ValueError("keys.private_key_path is required in config")

        self.root_key: bytes = load_key(private_key_path)
        self.stealth = StealthLayer(
            self.node_id,
            root_key=self.root_key,
            min_pad=0,
            max_pad=64,
            rotation_interval_sec=300,
        )

        # Dashboard backend URL
        self.dashboard_url: str | None = (
            "https://stealthmesh-backend.onrender.com/events"
        )

        # Defense engines
        self.alert_protocol = AlertProtocol(
            node_id=self.node_id,
            on_emit=self._handle_alert,
        )
        self.detection = DetectionEngine(
            node_id=self.node_id,
            alert_protocol=self.alert_protocol,
        )

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
            raise ValueError("Config file did not contain a YAML object")

        return data

    # ---------------- Networking ----------------

    def start_server(self) -> None:
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

                action = self.containment.get_action_for_suspect(suspect_id)

                if msg_type != "ALERT":
                    if action == "block":
                        print(
                            f"[{self.node_id}/Containment] BLOCKED message from {suspect_id}"
                        )
                        return
                    if action == "decoy":
                        self.deception.handle_decoy_request(
                            suspect_id, message, addr
                        )
                        return

                if msg_type == "ALERT":
                    print(f"[{self.node_id}] Received ALERT from peer: {message}")
                    self.containment.handle_peer_alert(message)
                else:
                    print(f"[{self.node_id}] Received from {addr}: {message}")
                    self.detection.handle_message(message, addr)

            except Exception as e:
                print(f"[{self.node_id}] Error handling client {addr}: {e}")
            finally:
                conn.close()

        while True:
            conn, addr = server_sock.accept()
            threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            ).start()

    def send_message(self, destination_id: str, message_dict: dict) -> None:
        next_hop = self.routing.get_next_hop(destination_id)
        if next_hop is None:
            raise ValueError(f"No route to destination_id={destination_id}")

        time.sleep(random.uniform(0.01, 0.2))
        ciphertext = self.stealth.encrypt_outgoing(message_dict)

        with socket.create_connection(
            (next_hop["host"], next_hop["port"]), timeout=5
        ) as sock:
            sock.sendall(ciphertext)

        print(
            f"[{self.node_id}] Sent message towards {destination_id} "
            f"via {next_hop['node_id']}"
        )

    def send_ping(self, target_node_id: str) -> None:
        self.send_message(
            target_node_id,
            {
                "type": "PING",
                "from": self.node_id,
                "timestamp": time.time(),
            },
        )

    def send_auth_fail_burst(self, target_node_id: str, count: int = 10) -> None:
        for i in range(count):
            self.send_message(
                target_node_id,
                {
                    "type": "AUTH_FAIL",
                    "from": self.node_id,
                    "payload": {"attempt": i + 1, "method": "SSH"},
                    "timestamp": time.time(),
                },
            )

    def send_port_probe_sweep(
        self, target_node_id: str, start_port: int = 10000, count: int = 20
    ) -> None:
        for i in range(count):
            self.send_message(
                target_node_id,
                {
                    "type": "PORT_PROBE",
                    "from": self.node_id,
                    "port": start_port + i,
                    "timestamp": time.time(),
                },
            )

    # ---------------- Dashboard ----------------

    def _send_event_to_dashboard(self, event: dict) -> None:
        if not self.dashboard_url:
            return
        try:
            requests.post(self.dashboard_url, json=event, timeout=3)
        except Exception as e:
            print(f"[{self.node_id}/Dashboard] Failed to send event: {e}")

    def push_status_loop(self, interval: int = 10) -> None:
        while True:
            self._send_event_to_dashboard(
                {
                    "type": "STATUS",
                    "node_id": self.node_id,
                    "timestamp": time.time(),
                    "data": {
                        "peers": list(self.peers_by_id.keys()),
                        "port": self.listen_port,
                    },
                }
            )
            time.sleep(interval)

    # ---------------- ALERT HANDLING ----------------

    def _handle_alert(self, alert: dict) -> None:
        print(f"[{self.node_id}][ALERT][LOCAL] {alert}")
        self.containment.handle_local_alert(alert)

        self._send_event_to_dashboard(
            {
                "type": "ALERT",
                "node_id": self.node_id,
                "timestamp": alert.get("timestamp"),
                "data": alert,
            }
        )

        self.broadcast_alert(alert)

    def broadcast_alert(self, alert: dict) -> None:
        for peer_id in self.peers_by_id:
            if peer_id != self.node_id:
                try:
                    self.send_message(peer_id, alert)
                except Exception as e:
                    print(f"[{self.node_id}] Broadcast error: {e}")

    # ---------------- CONTROL LOOP (NEW) ----------------

    def control_poll_loop(self, interval_sec: float = 2.0) -> None:
        """
        Poll backend for simulation commands assigned to this node.
        """
        if not self.dashboard_url:
            return

        control_url = self.dashboard_url.replace(
            "/events", f"/control/{self.node_id}"
        )

        while True:
            try:
                resp = requests.get(control_url, timeout=3)
                resp.raise_for_status()
                commands = resp.json()

                for cmd in commands:
                    print(f"[{self.node_id}] Executing simulation command: {cmd}")

                    attack_type = cmd.get("attack_type")
                    victim = cmd.get("victim")
                    count = int(cmd.get("count", 10))

                    if attack_type == "FAILED_LOGIN_BURST":
                        self.send_auth_fail_burst(victim, count)

                    elif attack_type == "PORT_SCAN":
                        self.send_port_probe_sweep(victim, count=count)

            except Exception as e:
                print(f"[{self.node_id}] Control poll error: {e}")

            time.sleep(interval_sec)

    # ---------------- Key Rotation ----------------

    def key_rotation_loop(self, interval_sec: float = 300.0) -> None:
        while True:
            try:
                self.stealth.rotate_keys()
            except Exception as e:
                print(f"[{self.node_id}] Key rotation error: {e}")
            time.sleep(interval_sec)


# ---------------- CLI ----------------


def main() -> None:
    parser = argparse.ArgumentParser(description="StealthMesh NodeAgent")
    parser.add_argument("node_id")
    parser.add_argument("config_path")
    args = parser.parse_args()

    agent = NodeAgent(args.config_path)

    server_thread = threading.Thread(target=agent.start_server, daemon=True)
    server_thread.start()

    threading.Thread(
        target=agent.key_rotation_loop, daemon=True
    ).start()

    threading.Thread(
        target=agent.push_status_loop, daemon=True
    ).start()

    # ✅ START CONTROL LOOP (REQUIRED)
    threading.Thread(
        target=agent.control_poll_loop, daemon=True
    ).start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print(f"[{agent.node_id}] Shutting down.")


if __name__ == "__main__":
    main()
