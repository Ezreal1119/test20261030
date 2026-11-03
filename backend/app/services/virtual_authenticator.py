from __future__ import annotations

import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.encode_cbor import encode_cbor


class VirtualAuthenticator:
    """Software authenticator used only to exercise the server verifier.

    It produces real ES256 signatures. It is not a shortcut around verification.
    """

    def __init__(self) -> None:
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    def cose_public_key(self) -> bytes:
        numbers = self._private_key.public_key().public_numbers()
        return encode_cbor(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def registration(self, *, challenge: bytes, rp_id: str, origin: str) -> dict:
        rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        flags = 0x01 | 0x04 | 0x40
        auth_data = (
            rp_hash
            + bytes([flags])
            + (0).to_bytes(4, "big")
            + bytes(16)
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + self.cose_public_key()
        )
        attestation = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = _client_data("webauthn.create", challenge, origin)
        credential_id = bytes_to_base64url(self.credential_id)
        return {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(attestation),
                "transports": ["internal"],
            },
        }

    def authentication(
        self,
        *,
        challenge: bytes,
        rp_id: str,
        origin: str,
        user_id: bytes,
        uv: bool = True,
        origin_override: str | None = None,
        rp_id_for_hash: str | None = None,
        challenge_override: bytes | None = None,
    ) -> dict:
        self.sign_count += 1
        flags = 0x01 | (0x04 if uv else 0)
        rp_hash = hashlib.sha256((rp_id_for_hash or rp_id).encode("utf-8")).digest()
        auth_data = rp_hash + bytes([flags]) + self.sign_count.to_bytes(4, "big")
        client_data = _client_data(
            "webauthn.get",
            challenge if challenge_override is None else challenge_override,
            origin_override or origin,
        )
        signature = self._sign(auth_data + hashlib.sha256(client_data).digest())
        credential_id = bytes_to_base64url(self.credential_id)
        return {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
                "userHandle": bytes_to_base64url(user_id),
            },
        }

    def _sign(self, data: bytes) -> bytes:
        der = self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        r_value, s_value = decode_dss_signature(der)
        return r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")


def _client_data(kind: str, challenge: bytes, origin: str) -> bytes:
    return json.dumps(
        {
            "type": kind,
            "challenge": bytes_to_base64url(challenge),
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")
