#!/usr/bin/env python3
"""
RE-KEM Hybrid Encryption
========================
Post-Quantum-Datenverschlüsselung: RE-KEM (Ring-LWE, IND-CCA2) tauscht ein
Shared Secret aus, AES-256-GCM verschlüsselt damit die Daten.

Warum hybrid? Ein KEM verschlüsselt nur einen Schlüssel (32 Byte), keine
beliebig großen Daten. Der Standardweg (wie bei RSA-OAEP + AES) ist:
  1. KEM.Encaps(pk) → Shared Secret (32 B)
  2. HKDF(Shared Secret) → AES-256-Key
  3. AES-GCM verschlüsselt die Daten

Nutzen:
  from rekem_hybrid import generate_keypair, encrypt, decrypt

  pk, sk = generate_keypair()
  blob = encrypt(pk, b"Geheime Daten")
  data = decrypt(sk, blob)
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys
from base64 import b64decode, b64encode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rekem import PostQuantumRingLWEKEM

# AES-256-GCM aus der Standardbibliothek-Ergänzung (cryptography) ODER
# reine stdlib-Variante unten. Wir nehmen cryptography, fällt auf Fehler zurück.
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAVE_AESGCM = True
except ImportError:  # pragma: no cover
    _HAVE_AESGCM = False

MAGIC = b"REKEM1"  # Format-Marker
_KEM = PostQuantumRingLWEKEM()


def _hkdf(shared_secret: bytes, info: bytes = b"re-kem-aes256gcm", length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869) — deterministisch aus dem Shared Secret."""
    # Extract
    salt = b"\x00" * 32
    prk = _hmac(salt, shared_secret)
    # Expand
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = _hmac(prk, t + info + bytes([i]))
        okm += t
        i += 1
    return okm[:length]


def _hmac(key: bytes, msg: bytes) -> bytes:
    import hmac
    return hmac.new(key, msg, hashlib.sha256).digest()


def generate_keypair() -> tuple[bytes, bytes]:
    """Erzeugt (Public Key, Secret Key) — post-quantum Ring-LWE."""
    return _KEM.keygen()


def encrypt(pk: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Verschlüsselt Daten mit dem Public Key.

    Format: MAGIC | ct_len(2) | kem_ct | nonce(12) | aes_ct
    """
    kem_ct, shared_secret = _KEM.encaps(pk)
    key = _hkdf(shared_secret)
    nonce = os.urandom(12)

    if _HAVE_AESGCM:
        aes = AESGCM(key)
        aes_ct = aes.encrypt(nonce, plaintext, aad or None)
    else:  # pragma: no cover
        raise RuntimeError("cryptography-Paket fehlt: pip install cryptography")

    return MAGIC + struct.pack(">H", len(kem_ct)) + kem_ct + nonce + aes_ct


def decrypt(sk: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Entschlüsselt ein Blob mit dem Secret Key."""
    if not blob.startswith(MAGIC):
        raise ValueError("Unbekanntes Format (MAGIC fehlt)")
    off = len(MAGIC)
    (kem_len,) = struct.unpack(">H", blob[off:off + 2])
    off += 2
    kem_ct = blob[off:off + kem_len]
    off += kem_len
    nonce = blob[off:off + 12]
    off += 12
    aes_ct = blob[off:]

    shared_secret = _KEM.decaps(sk, kem_ct)
    key = _hkdf(shared_secret)

    if _HAVE_AESGCM:
        aes = AESGCM(key)
        return aes.decrypt(nonce, aes_ct, aad or None)

    raise RuntimeError("cryptography-Paket fehlt: pip install cryptography")  # pragma: no cover


def encrypt_b64(pk: bytes, plaintext: bytes, aad: bytes = b"") -> str:
    """Wie encrypt(), aber Base64-kodiert (für JSON/Text-Transport)."""
    return b64encode(encrypt(pk, plaintext, aad)).decode()


def decrypt_b64(sk: bytes, blob_b64: str, aad: bytes = b"") -> bytes:
    return decrypt(sk, b64decode(blob_b64), aad)
