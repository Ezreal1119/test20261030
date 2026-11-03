from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint_hex(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def compare_secret(presented: str, expected: str) -> bool:
    if not expected:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def ecdsa_signature_to_der(signature: bytes) -> bytes:
    """WebAuthn ES256 signatures are raw r||s. cryptography verifies DER."""
    if len(signature) != 64:
        return signature
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r == 0 or s == 0:
        return signature
    return encode_dss_signature(r, s)
