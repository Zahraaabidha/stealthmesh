import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# We'll use a single symmetric key per node for now (AES-GCM 256-bit).
KEY_SIZE_BYTES = 32  # 256-bit


def generate_keypair() -> bytes:
    """
    For now, this just generates a random symmetric key.
    (Name is 'keypair' for future compatibility.)
    """
    return AESGCM.generate_key(bit_length=256)


def load_key(path: str | Path) -> bytes:
    """
    Load a symmetric key from a file.
    If the file does not exist, create a new random key and save it.
    """
    path = Path(path)
    if path.exists():
        return path.read_bytes()

    # Create new key and persist it
    key = generate_keypair()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    return key


def encrypt_symmetric(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt bytes using AES-GCM.
    We prepend the nonce (12 bytes) to the ciphertext.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # AES-GCM standard nonce length
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext  # nonce || ciphertext


def decrypt_symmetric(key: bytes, data: bytes) -> bytes:
    """
    Decrypt bytes using AES-GCM.
    Expects input as nonce || ciphertext.
    """
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext
