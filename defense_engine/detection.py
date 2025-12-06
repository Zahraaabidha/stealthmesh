from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, Any, Tuple, Set, List

from .alert_protocol import AlertProtocol

# --- Optional ML imports ---
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
except ImportError:
    IsolationForest = None
    np = None


class DetectionEngine:
    """
    Local detection rules for suspicious behavior.

    - Rule-based:
        * Failed logins via messages of type "AUTH_FAIL".
        * Port scans via messages of type "PORT_PROBE" with a 'port' field.
    - Optional ML-based anomaly detection using IsolationForest:
        * Builds simple feature vectors per suspect and learns a baseline.
    """

    # Rule-based thresholds
    FAILED_LOGIN_WINDOW_SEC = 60        # 1 minute
    FAILED_LOGIN_THRESHOLD = 5          # > 5 failures per window => alert

    PORT_SCAN_WINDOW_SEC = 30           # 30 seconds
    PORT_SCAN_PORT_THRESHOLD = 10       # > 10 distinct ports in window => alert

    # ML parameters
    ML_MIN_BASELINE_SAMPLES = 50        # how many feature samples before training
    ML_ANOMALY_THRESHOLD = 0.6          # higher => more strict (0..1-ish)

    def __init__(self, node_id: str, alert_protocol: AlertProtocol, ml_enabled: bool = True):
        self.node_id = node_id
        self.alert_protocol = alert_protocol

        # --- Rule-based state ---
        # (suspect_id, window_start) -> count
        self.failed_logins: Dict[Tuple[str, int], int] = defaultdict(int)

        # (suspect_id, window_start) -> set of ports
        self.scanned_ports: Dict[Tuple[str, int], Set[int]] = defaultdict(set)

        # --- ML state ---
        self.ml_enabled = ml_enabled and IsolationForest is not None and np is not None
        self.ml_baseline_features: List["np.ndarray"] = []
        self.ml_model: "IsolationForest | None" = None
        self.ml_trained: bool = False

        if not self.ml_enabled:
            print(f"[{self.node_id}/Detection][ML] ML disabled (sklearn or numpy missing, "
                  f"or ml_enabled=False).")
        else:
            print(f"[{self.node_id}/Detection][ML] ML anomaly detection ENABLED.")

    # --------- Public entrypoint ---------

    def handle_message(self, message: Dict[str, Any], addr: Tuple[str, int]) -> None:
        """
        Inspect a received message and update detection state.
        """
        msg_type = message.get("type")
        suspect_id = message.get("from") or f"{addr[0]}:{addr[1]}"

        # --- Rule-based ---
        if msg_type == "AUTH_FAIL":
            self._record_failed_login(suspect_id)
        elif msg_type == "PORT_PROBE":
            port = self._extract_port(message)
            if port is not None:
                self._record_port_probe(suspect_id, port)
        else:
            # For now ignore other types in rule-based logic (PING, COVER, ALERT, ...)
            pass

        # --- ML-based anomaly detection (optional) ---
        self._maybe_run_ml_detection(suspect_id)

    # --------- Window helpers ---------

    def _current_window_start(self, window_sec: int) -> int:
        """
        Compute the start timestamp (integer) of the current window.
        """
        now = int(time.time())
        return now - (now % window_sec)

    # --------- Failed login rule ---------

    def _record_failed_login(self, suspect_id: str) -> None:
        window = self._current_window_start(self.FAILED_LOGIN_WINDOW_SEC)
        key = (suspect_id, window)
        self.failed_logins[key] += 1

        count = self.failed_logins[key]
        print(f"[{self.node_id}/Detection] AUTH_FAIL from {suspect_id}, "
              f"count={count} in window starting {window}")

        if count > self.FAILED_LOGIN_THRESHOLD:
            reason = f"Too many failed logins: {count} in {self.FAILED_LOGIN_WINDOW_SEC}s"
            self.alert_protocol.emit_alert(
                suspect=suspect_id,
                reason=reason,
                confidence=0.9,
                extra={"type": "FAILED_LOGIN_BURST", "count": count},
            )

    # --------- Port scan rule ---------

    def _extract_port(self, message: Dict[str, Any]) -> int | None:
        """
        Try to extract a port number from the message.
        We expect either:
        - message["port"], or
        - message["payload"]["port"]
        """
        if "port" in message:
            try:
                return int(message["port"])
            except (TypeError, ValueError):
                return None

        payload = message.get("payload")
        if isinstance(payload, dict) and "port" in payload:
            try:
                return int(payload["port"])
            except (TypeError, ValueError):
                return None

        return None

    def _record_port_probe(self, suspect_id: str, port: int) -> None:
        window = self._current_window_start(self.PORT_SCAN_WINDOW_SEC)
        key = (suspect_id, window)
        ports = self.scanned_ports[key]
        ports.add(port)

        print(f"[{self.node_id}/Detection] PORT_PROBE from {suspect_id} on port={port}, "
              f"unique_ports={len(ports)} in window starting {window}")

        if len(ports) > self.PORT_SCAN_PORT_THRESHOLD:
            reason = (f"Possible port scan: {len(ports)} distinct ports in "
                      f"{self.PORT_SCAN_WINDOW_SEC}s")
            self.alert_protocol.emit_alert(
                suspect=suspect_id,
                reason=reason,
                confidence=0.85,
                extra={"type": "PORT_SCAN", "ports": sorted(ports)},
            )

    # --------- ML feature building ---------

    def _build_feature_vector(self, suspect_id: str) -> "np.ndarray | None":
        """
        Construct a simple feature vector for a given suspect.
        Features (example):
          - total_failed_logins (last window)
          - total_ports_scanned (last window)
        You can expand later with more dimensions.
        """
        if not self.ml_enabled:
            return None

        now = int(time.time())

        # Failed login count in current window
        fl_window = self._current_window_start(self.FAILED_LOGIN_WINDOW_SEC)
        fl_key = (suspect_id, fl_window)
        failed_count = float(self.failed_logins.get(fl_key, 0))

        # Port scan distinct ports in current window
        ps_window = self._current_window_start(self.PORT_SCAN_WINDOW_SEC)
        ps_key = (suspect_id, ps_window)
        port_count = float(len(self.scanned_ports.get(ps_key, set())))

        # Very simple 2D vector
        vec = np.array([failed_count, port_count], dtype=float)
        return vec

    # --------- ML anomaly detection ---------

    def _maybe_run_ml_detection(self, suspect_id: str) -> None:
        if not self.ml_enabled:
            return
        if IsolationForest is None or np is None:
            return

        fv = self._build_feature_vector(suspect_id)
        if fv is None:
            return

        # During baseline collection (no model yet), just store typical behavior
        if not self.ml_trained:
            self.ml_baseline_features.append(fv)

            if len(self.ml_baseline_features) >= self.ML_MIN_BASELINE_SAMPLES:
                # Train IsolationForest on baseline
                X = np.stack(self.ml_baseline_features, axis=0)
                self.ml_model = IsolationForest(
                    n_estimators=100,
                    contamination="auto",
                    random_state=42,
                )
                self.ml_model.fit(X)
                self.ml_trained = True
                print(f"[{self.node_id}/Detection][ML] Trained IsolationForest on "
                      f"{len(self.ml_baseline_features)} baseline samples.")
            return

        # If we have a model, compute anomaly score for this vector
        if self.ml_model is None:
            return

        X_test = fv.reshape(1, -1)
        # IsolationForest: lower score => more anomalous.
        # We'll convert to a 0..1-ish "anomaly_score".
        raw_score = self.ml_model.score_samples(X_test)[0]
        anomaly_score = float(-raw_score)  # invert

        print(f"[{self.node_id}/Detection][ML] suspect={suspect_id} "
              f"features={fv.tolist()} anomaly_score={anomaly_score:.3f}")

        if anomaly_score >= self.ML_ANOMALY_THRESHOLD:
            reason = f"ML anomaly score {anomaly_score:.3f} for suspect {suspect_id}"
            self.alert_protocol.emit_alert(
                suspect=suspect_id,
                reason=reason,
                confidence=0.75,
                extra={
                    "type": "ML_ANOMALY",
                    "anomaly_score": anomaly_score,
                    "features": fv.tolist(),
                },
            )
