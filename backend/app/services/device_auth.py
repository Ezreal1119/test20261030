from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509

from app.config import get_settings
from app.db import connect, expires_in, transaction, utcnow
from app.errors import VerificationRejected
from app.services.attestation import UNVERIFIED, verify_attestation
from app.services.encoding import b64url_decode, b64url_encode, fingerprint_hex, token_hash


def create_enrollment_token() -> dict:
    token = "enr_" + secrets.token_urlsafe(32)
    now = utcnow()
    expires = expires_in(24 * 60 * 60)
    with transaction() as conn:
        conn.execute(
            "INSERT INTO enrollment_tokens(token_hash, created_at, expires_at) VALUES(?, ?, ?)",
            (token_hash(token), now, expires),
        )
    return {"ok": True, "enrollment_token": token, "expires_at": expires}


def create_attestation_challenge() -> dict:
    challenge = secrets.token_bytes(32)
    challenge_id = str(uuid.uuid4())
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO attestation_challenges(challenge_id, challenge, created_at, expires_at)
            VALUES(?, ?, ?, ?)
            """,
            (challenge_id, challenge, utcnow(), expires_in(600)),
        )
    return {"ok": True, "challenge_id": challenge_id, "challenge": b64url_encode(challenge)}


def register_device(body: dict) -> dict:
    token = str(body.get("enrollment_token", "")).strip()
    if not token:
        raise VerificationRejected("Enrollment token is required")
    try:
        spki = b64url_decode(str(body.get("public_key_spki", "")))
    except Exception as exc:
        raise VerificationRejected("Public key encoding is invalid") from exc
    _require_p256(spki)
    fingerprint = fingerprint_hex(spki)
    supplied = str(body.get("fingerprint", "")).replace(" ", "").upper()
    if supplied and supplied != fingerprint:
        raise VerificationRejected("Public key fingerprint does not match the public key")
    exportable = bool(body.get("private_key_exportable", True))
    security_level = str(body.get("security_level", "UNKNOWN"))[:64]
    attestation = _attestation_result(body, spki)
    device_info = json.dumps(body.get("device_info") or {}, separators=(",", ":"))[:8000]
    replace_id = str(body.get("replace_registration_id") or "").strip()
    now = utcnow()
    with transaction() as conn:
        token_row = conn.execute(
            "SELECT * FROM enrollment_tokens WHERE token_hash = ?",
            (token_hash(token),),
        ).fetchone()
        if token_row is None or token_row["used_at"] is not None or token_row["expires_at"] <= now:
            raise VerificationRejected("Enrollment token is invalid, used, or expired")
        existing = conn.execute(
            "SELECT registration_id FROM devices WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if replace_id:
            target = conn.execute(
                "SELECT registration_id FROM devices WHERE registration_id = ?",
                (replace_id,),
            ).fetchone()
            if target is None:
                raise VerificationRejected("Device registration to replace was not found")
            if existing is not None and existing["registration_id"] != replace_id:
                raise VerificationRejected("That public key is already registered to another device")
            conn.execute(
                """
                UPDATE devices
                SET public_key_spki = ?, fingerprint = ?, algorithm = ?, security_level = ?,
                    user_authentication_required = ?, private_key_exportable = ?, key_alias = ?,
                    attestation_status = ?, attestation_level = ?, device_info_json = ?, updated_at = ?
                WHERE registration_id = ?
                """,
                (
                    spki,
                    fingerprint,
                    "ECDSA P-256 SHA-256",
                    security_level,
                    1 if body.get("user_authentication_required") else 0,
                    1 if exportable else 0,
                    str(body.get("key_alias", ""))[:128],
                    attestation["status"],
                    attestation["security_level"],
                    device_info,
                    now,
                    replace_id,
                ),
            )
            registration_id = replace_id
            created = False
        elif existing is not None:
            registration_id = existing["registration_id"]
            conn.execute(
                """
                UPDATE devices
                SET attestation_status = ?, attestation_level = ?, device_info_json = ?, updated_at = ?,
                    security_level = ?, private_key_exportable = ?, user_authentication_required = ?
                WHERE registration_id = ?
                """,
                (
                    attestation["status"],
                    attestation["security_level"],
                    device_info,
                    now,
                    security_level,
                    1 if exportable else 0,
                    1 if body.get("user_authentication_required") else 0,
                    registration_id,
                ),
            )
            created = False
        else:
            registration_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO devices(
                    registration_id, public_key_spki, fingerprint, algorithm, security_level,
                    user_authentication_required, private_key_exportable, key_alias,
                    attestation_status, attestation_level, device_info_json, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    registration_id,
                    spki,
                    fingerprint,
                    "ECDSA P-256 SHA-256",
                    security_level,
                    1 if body.get("user_authentication_required") else 0,
                    1 if exportable else 0,
                    str(body.get("key_alias", ""))[:128],
                    attestation["status"],
                    attestation["security_level"],
                    device_info,
                    now,
                    now,
                ),
            )
            created = True
        conn.execute(
            "UPDATE enrollment_tokens SET used_at = ? WHERE token_hash = ?",
            (now, token_hash(token)),
        )
    return {
        "ok": True,
        "registration_id": registration_id,
        "created": created,
        "fingerprint": fingerprint,
        "attestation_status": attestation["status"],
        "private_key_exportable": exportable,
    }


def create_device_challenge(registration_id: str, transaction_id: str | None = None) -> dict:
    device = get_device(registration_id)
    if device is None:
        raise VerificationRejected("Unknown device")
    challenge = secrets.token_bytes(32)
    challenge_id = str(uuid.uuid4())
    expires = expires_in(get_settings().challenge_ttl_seconds)
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO device_challenges(
                challenge_id, registration_id, challenge, transaction_id, created_at, expires_at
            ) VALUES(?, ?, ?, ?, ?, ?)
            """,
            (challenge_id, registration_id, challenge, transaction_id, utcnow(), expires),
        )
    return {
        "ok": True,
        "challenge_id": challenge_id,
        "challenge": b64url_encode(challenge),
        "registration_id": registration_id,
        "expires_at": expires,
    }


def verify_device_challenge(challenge_id: str, signature_b64: str) -> dict:
    try:
        signature = b64url_decode(signature_b64)
    except Exception as exc:
        raise VerificationRejected("Device signature encoding is invalid") from exc
    row = _claim_device_challenge(challenge_id)
    device = get_device(row["registration_id"])
    if device is None:
        _audit(row["registration_id"], challenge_id, False, "Unknown device")
        raise VerificationRejected("Unknown device")
    try:
        verify_device_signature(device["public_key_spki"], bytes(row["challenge"]), signature)
    except VerificationRejected as exc:
        _audit(row["registration_id"], challenge_id, False, str(exc))
        raise
    _audit(row["registration_id"], challenge_id, True, "Device signature verified")
    return {
        "ok": True,
        "registration_id": row["registration_id"],
        "message": "Device signature verified",
    }


def verify_device_signature(spki: bytes, challenge: bytes, signature: bytes) -> None:
    key = _require_p256(spki)
    try:
        key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise VerificationRejected("Device signature was rejected") from exc


def get_device(registration_id: str) -> dict | None:
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM devices WHERE registration_id = ?",
            (registration_id,),
        ).fetchone()
        return None if row is None else dict(row)
    finally:
        conn.close()


def _claim_device_challenge(challenge_id: str):
    with transaction() as conn:
        row = conn.execute(
            "SELECT * FROM device_challenges WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
        if row is None:
            raise VerificationRejected("Unknown device challenge")
        if row["used_at"] is not None:
            raise VerificationRejected("Replayed device challenge")
        if row["expires_at"] <= utcnow():
            raise VerificationRejected("Expired device challenge")
        updated = conn.execute(
            "UPDATE device_challenges SET used_at = ? WHERE challenge_id = ? AND used_at IS NULL",
            (utcnow(), challenge_id),
        )
        if updated.rowcount != 1:
            raise VerificationRejected("Replayed device challenge")
        return dict(row)


def _audit(registration_id: str | None, challenge_id: str | None, accepted: bool, reason: str) -> None:
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO device_verify_events(registration_id, challenge_id, accepted, reason, created_at)
            VALUES(?, ?, ?, ?, ?)
            """,
            (registration_id, challenge_id, 1 if accepted else 0, reason[:300], utcnow()),
        )


def _require_p256(spki: bytes):
    try:
        key = serialization.load_der_public_key(spki)
    except Exception as exc:
        raise VerificationRejected("Public key could not be parsed") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise VerificationRejected("Registered key is not ECDSA P-256")
    return key


def _attestation_result(body: dict, spki: bytes) -> dict:
    chain_values = body.get("attestation_chain") or []
    challenge_id = str(body.get("attestation_challenge_id") or "").strip()
    if not chain_values:
        return {"status": f"{UNVERIFIED} No attestation certificate chain was submitted.", "security_level": None}
    if not challenge_id:
        return {"status": f"{UNVERIFIED} No attestation challenge was bound to this key.", "security_level": None}
    if not isinstance(chain_values, list) or len(chain_values) > 8:
        return {"status": f"{UNVERIFIED} Attestation chain was rejected.", "security_level": None}
    try:
        certificates = [x509.load_der_x509_certificate(b64url_decode(str(item))) for item in chain_values]
    except Exception:
        return {"status": f"{UNVERIFIED} Attestation certificates could not be parsed.", "security_level": None}
    with transaction() as conn:
        row = conn.execute(
            "SELECT * FROM attestation_challenges WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
        if row is None or row["used_at"] is not None or row["expires_at"] <= utcnow():
            return {"status": f"{UNVERIFIED} Attestation challenge is unknown, used, or expired.", "security_level": None}
        conn.execute(
            "UPDATE attestation_challenges SET used_at = ? WHERE challenge_id = ?",
            (utcnow(), challenge_id),
        )
        challenge = bytes(row["challenge"])
    return verify_attestation(certificates, challenge, spki)
