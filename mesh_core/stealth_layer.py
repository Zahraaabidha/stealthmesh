from __future__ import annotations

import json
import os
import random
import time
import hmac
import hashlib
from typing import Any, Dict

from .crypto_utils import encrypt_symmetric, decrypt_symmetric


class StealthLayer:
    """
    StealthLayer sits between NodeAgent and the raw crypto.

    Responsibilities:
    - Hold a long-term root key.
    - Derive time-based session keys (key rotation / polymorphism).
    - Handle JSON <-> bytes.
    - Add / remove random padding.

    Session keys are derived deterministically from:
        root_key, epoch = floor(time / rotation_interval_sec)

    So all nodes that share root_key + interval will stay in sync.
    """

    def __init__(
        self,
        node_id: str,
        root_key: bytes,
        min_pad: int = 0,
        max_pad: int = 64,
        rotation_interval_sec: int = 300,
    ):
        self.node_id = node_id
        self.root_key = root_key
        self.min_pad = min_pad
        self.max_pad = max_pad
        self.rotation_interval_sec = rotation_interval_sec

        # Initialize session key for current epoch
        self.current_epoch = self._current_epoch()
        self.session_key = self._derive_session_key(self.current_epoch)

    # ----- Epoch / key derivation helpers -----

    def _current_epoch(self) -> int:
        """
        Compute the current epoch index based on wall-clock time
        and the rotation interval.
        """
        return int(time.time() // self.rotation_interval_sec)

    def _derive_session_key(self, epoch: int) -> bytes:
        """
        Derive a 32-byte session key from the root key and epoch
        using HMAC-SHA256(root_key, epoch_bytes).
        """
        epoch_bytes = epoch.to_bytes(8, "big")
        return hmac.new(self.root_key, epoch_bytes, hashlib.sha256).digest()

    # ----- Padding helpers -----

    def _add_padding(self, data: bytes) -> bytes:
        """
        Add random-length padding.

        Layout of plaintext before encryption:
        [2 bytes pad_len][data][pad_len bytes random padding]
        """
        pad_len = random.randint(self.min_pad, self.max_pad)
        padding = os.urandom(pad_len)
        header = pad_len.to_bytes(2, "big")  # supports up to 65535 bytes of padding
        return header + data + padding

    def _remove_padding(self, padded: bytes) -> bytes:
        """
        Inverse of _add_padding.

        Expects: [2 bytes pad_len][data][pad_len bytes padding]
        Returns: original data bytes.
        """
        if len(padded) < 2:
            raise ValueError("Padded data too short to contain header")

        pad_len = int.from_bytes(padded[:2], "big")
        body = padded[2:]

        if pad_len > len(body):
            raise ValueError("Invalid padding length in StealthLayer")

        if pad_len == 0:
            return body

        return body[:-pad_len]

    # ----- Core transform methods -----

    def encrypt_outgoing(self, message: Dict[str, Any]) -> bytes:
        """
        Take a Python dict, JSON-encode it, pad it, and encrypt it
        with the current session key.
        """
        plaintext = json.dumps(message).encode("utf-8")
        padded_plaintext = self._add_padding(plaintext)
        ciphertext = encrypt_symmetric(self.session_key, padded_plaintext)
        return ciphertext

    def decrypt_incoming(self, data: bytes) -> Dict[str, Any]:
        """
        Decrypt bytes, remove padding, and parse JSON back to a dict.

        This uses the current session key. For robustness you could
        also try the previous epoch's key if decryption fails.
        """
        padded_plaintext = decrypt_symmetric(self.session_key, data)
        plaintext = self._remove_padding(padded_plaintext)
        message = json.loads(plaintext.decode("utf-8"))
        return message

    # ----- Key rotation (polymorphic behavior) -----

    def rotate_keys(self) -> None:
        """
        Check whether we've crossed into a new epoch; if so,
        derive a new session key from the root key and update.
        """
        new_epoch = self._current_epoch()
        if new_epoch != self.current_epoch:
            self.current_epoch = new_epoch
            self.session_key = self._derive_session_key(new_epoch)
            print(f"[{self.node_id}/Stealth] Rotated session key, epoch={new_epoch}")
