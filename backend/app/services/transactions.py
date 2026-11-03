from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.db import connect, expires_in, millis_between, transaction, utcnow
from app.errors import ApiError, VerificationRejected
from app.services.device_auth import create_device_challenge, get_device, verify_device_challenge
from app.services.webauthn_service import create_authentication_options, finish_authentication


def start_transaction(registration_id: str, username: str) -> dict:
    if get_device(registration_id) is None:
        raise VerificationRejected("Unknown device")
    from app.services.webauthn_service import _credentials_for

    if not _credentials_for(username):
        raise VerificationRejected("Register a Passkey for this username before complete authentication")
    transaction_id = str(uuid.uuid4())
    challenge = create_device_challenge(registration_id, transaction_id)
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO auth_transactions(
                transaction_id, registration_id, username, state, device_challenge_id, created_at
            ) VALUES(?, ?, ?, 'pending_device', ?, ?)
            """,
            (transaction_id, registration_id, username, challenge["challenge_id"], utcnow()),
        )
    return {
        "ok": True,
        "transaction_id": transaction_id,
        "challenge_id": challenge["challenge_id"],
        "challenge": challenge["challenge"],
        "expires_at": expires_in(get_settings().transaction_ttl_seconds),
    }


def submit_device(transaction_id: str, signature: str) -> dict:
    current = _require_transaction(transaction_id)
    _require_fresh(current)
    if current["state"] != "pending_device":
        raise VerificationRejected("Device authentication is not pending for this transaction")
    try:
        verify_device_challenge(current["device_challenge_id"], signature)
    except VerificationRejected as exc:
        _fail(transaction_id, "FAIL", current["webauthn_result"], str(exc))
        raise
    try:
        options = create_authentication_options(current["username"], transaction_id)
    except VerificationRejected as exc:
        _fail(transaction_id, "PASS", "FAIL", str(exc))
        raise
    with transaction() as conn:
        conn.execute(
            """
            UPDATE auth_transactions
            SET state = 'device_verified', device_result = 'PASS', webauthn_challenge_id = ?
            WHERE transaction_id = ?
            """,
            (options["challenge_id"], transaction_id),
        )
    return {
        "ok": True,
        "device_authenticated": True,
        "transaction_id": transaction_id,
        "request_json": options["request_json"],
        "webauthn_challenge_id": options["challenge_id"],
    }


def submit_webauthn(transaction_id: str, credential_json: str | dict) -> dict:
    current = _require_transaction(transaction_id)
    _require_fresh(current)
    if current["state"] != "device_verified":
        raise VerificationRejected("Device authentication has not succeeded for this transaction")
    try:
        verified = finish_authentication(current["webauthn_challenge_id"], credential_json, transaction_id)
    except VerificationRejected as exc:
        _fail(transaction_id, "PASS", "FAIL", str(exc))
        raise
    session = _create_session(current)
    with transaction() as conn:
        conn.execute(
            """
            UPDATE auth_transactions
            SET state = 'completed', webauthn_result = 'PASS', session_id = ?, completed_at = ?,
                failure_reason = NULL
            WHERE transaction_id = ? AND state = 'device_verified'
            """,
            (session["session_id"], utcnow(), transaction_id),
        )
    return {
        "ok": True,
        "session_token": session["token"],
        "expires_at": session["expires_at"],
        "transaction_id": transaction_id,
        "summary": verified["summary"],
        "user_verified": verified["user_verified"],
        "backup_eligible": verified["backup_eligible"],
        "backup_state": verified["backup_state"],
    }


def cancel_transaction(transaction_id: str, reason: str) -> dict:
    current = _require_transaction(transaction_id)
    if current["state"] == "completed":
        raise VerificationRejected("A completed authentication transaction cannot be cancelled")
    cleaned = (reason or "Authentication cancelled").strip()[:300]
    with transaction() as conn:
        if current["state"] != "failed":
            conn.execute(
                """
                UPDATE auth_transactions
                SET state = 'failed', failed_at = ?, failure_reason = ?,
                    device_result = COALESCE(NULLIF(device_result, ''), 'FAIL'),
                    webauthn_result = COALESCE(NULLIF(webauthn_result, ''), 'FAIL')
                WHERE transaction_id = ?
                """,
                (utcnow(), cleaned, transaction_id),
            )
        else:
            conn.execute(
                """
                UPDATE auth_transactions
                SET webauthn_result = COALESCE(NULLIF(webauthn_result, ''), 'FAIL'),
                    failure_reason = COALESCE(failure_reason, ?)
                WHERE transaction_id = ?
                """,
                (cleaned, transaction_id),
            )
    return {"ok": True, "transaction_id": transaction_id, "state": "failed"}


def read_session(token: str) -> dict:
    row = _session_row(token)
    if row is None:
        raise ApiError("Session is unknown", 401)
    if row["expires_at"] <= utcnow():
        raise ApiError("Session is expired", 401)
    return {
        "ok": True,
        "active": True,
        "username": row["username"],
        "registration_id": row["registration_id"],
        "transaction_id": row["transaction_id"],
        "expires_at": row["expires_at"],
    }


def logout(token: str) -> dict:
    with transaction() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash(token),))
    return {"ok": True}


def record_attempt(body: dict) -> dict:
    total = _non_negative(body.get("total_ms"), "total_ms")
    device_ms = _non_negative(body.get("device_ms"), "device_ms")
    webauthn_ms = _non_negative(body.get("webauthn_ms"), "webauthn_ms")
    session_ms = _non_negative(body.get("session_ms"), "session_ms")
    if abs((device_ms + webauthn_ms + session_ms) - total) > 5:
        raise VerificationRejected("Duration segments do not add up to the total")
    if total > 30 * 60 * 1000:
        raise VerificationRejected("Reported duration is outside the accepted recording range")
    device_result = _result(body.get("device_result"))
    webauthn_result = _result(body.get("webauthn_result"))
    session_result = _result(body.get("session_result"))
    transaction_id = str(body.get("transaction_id") or "").strip()
    current = _require_transaction(transaction_id) if transaction_id else None
    corroborated = 0
    server_window = None
    if session_result == "PASS":
        if current is None or current["state"] != "completed":
            raise VerificationRejected("A passing attempt requires a completed authentication transaction")
        if current["device_result"] != "PASS" or current["webauthn_result"] != "PASS":
            raise VerificationRejected("Transaction results do not match a passing attempt")
        if device_result != "PASS" or webauthn_result != "PASS":
            raise VerificationRejected("Client results do not match the completed transaction")
        if not _session_for_transaction(transaction_id):
            raise VerificationRejected("Completed transaction has no session")
        corroborated = 1
        server_window = millis_between(current["created_at"], current["completed_at"])
    else:
        if current is None:
            if not str(body.get("failure_reason") or "").strip():
                raise VerificationRejected("A failed attempt needs a transaction or a failure reason")
        else:
            if current["state"] != "failed":
                raise VerificationRejected("Failed attempt does not match the transaction state")
            if current["device_result"] and device_result != current["device_result"]:
                raise VerificationRejected("Device result does not match the transaction")
            if current["webauthn_result"] and webauthn_result != current["webauthn_result"]:
                raise VerificationRejected("WebAuthn result does not match the transaction")
            corroborated = 1
            if current["failed_at"]:
                server_window = millis_between(current["created_at"], current["failed_at"])
    discrepancy = 0
    if server_window is not None and abs(total - server_window) > 15000:
        discrepancy = 1
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO attempts(
                recorded_at, transaction_id, registration_id, total_ms, device_ms, webauthn_ms,
                session_ms, device_result, webauthn_result, session_result, network_type,
                failure_reason, device_info_json, corroborated, server_window_ms, timer_discrepancy
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utcnow(),
                transaction_id or None,
                str(body.get("registration_id") or "") or None,
                total,
                device_ms,
                webauthn_ms,
                session_ms,
                device_result,
                webauthn_result,
                session_result,
                str(body.get("network_type") or "")[:32],
                str(body.get("failure_reason") or "")[:300],
                json.dumps(body.get("device_info") or {})[:8000],
                corroborated,
                server_window,
                discrepancy,
            ),
        )
    return {"ok": True, "corroborated": bool(corroborated), "server_window_ms": server_window, "timer_discrepancy": bool(discrepancy)}


def _create_session(current: dict) -> dict:
    token = secrets.token_urlsafe(32)
    session_id = str(uuid.uuid4())
    expires = expires_in(get_settings().session_ttl_seconds)
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO sessions(
                session_id, token_hash, transaction_id, registration_id, username, created_at, expires_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                _hash(token),
                current["transaction_id"],
                current["registration_id"],
                current["username"],
                utcnow(),
                expires,
            ),
        )
    return {"session_id": session_id, "token": token, "expires_at": expires}


def _fail(transaction_id: str, device_result: str, webauthn_result: str | None, reason: str) -> None:
    with transaction() as conn:
        conn.execute(
            """
            UPDATE auth_transactions
            SET state = 'failed', failed_at = ?, failure_reason = ?,
                device_result = ?, webauthn_result = ?
            WHERE transaction_id = ? AND state != 'completed'
            """,
            (utcnow(), reason[:300], device_result, webauthn_result, transaction_id),
        )


def _require_transaction(transaction_id: str) -> dict:
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM auth_transactions WHERE transaction_id = ?",
            (transaction_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise VerificationRejected("Authentication transaction was not found")
    return dict(row)


def _require_fresh(current: dict) -> None:
    created = datetime.fromisoformat(current["created_at"])
    limit = created + timedelta(seconds=get_settings().transaction_ttl_seconds)
    if datetime.now(timezone.utc) > limit:
        _fail(current["transaction_id"], current["device_result"] or "FAIL", current["webauthn_result"], "Authentication transaction expired")
        raise VerificationRejected("Authentication transaction expired")


def _session_row(token: str) -> dict | None:
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM sessions WHERE token_hash = ?", (_hash(token),)).fetchone()
        return None if row is None else dict(row)
    finally:
        conn.close()


def _session_for_transaction(transaction_id: str) -> bool:
    conn = connect()
    try:
        row = conn.execute(
            "SELECT session_id FROM sessions WHERE transaction_id = ?",
            (transaction_id,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _non_negative(value: object, name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise VerificationRejected(f"{name} is not an integer") from exc
    if number < 0:
        raise VerificationRejected(f"{name} cannot be negative")
    return number


def _result(value: object) -> str:
    text = str(value or "").upper()
    if text not in {"PASS", "FAIL"}:
        raise VerificationRejected("Authentication results must be PASS or FAIL")
    return text
