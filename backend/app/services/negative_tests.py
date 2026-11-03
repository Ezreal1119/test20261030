from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.config import get_settings
from app.db import connect, transaction, utcnow
from app.errors import VerificationRejected
from app.services.device_auth import (
    create_device_challenge,
    create_enrollment_token,
    register_device,
    verify_device_challenge,
)
from app.services.encoding import b64url_decode, b64url_encode, fingerprint_hex
from app.services.transactions import start_transaction, submit_device, submit_webauthn
from app.services.virtual_authenticator import VirtualAuthenticator
from app.services.webauthn_service import (
    create_authentication_options,
    create_registration_options,
    finish_authentication,
    finish_registration,
)


def run_negative_tests() -> dict:
    username = "negtest-" + os.urandom(4).hex()
    registration_ids: list[str] = []
    results: list[dict] = []
    try:
        device_key = ec.generate_private_key(ec.SECP256R1())
        spki = device_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        registration_id = _enroll(username, spki)
        registration_ids.append(registration_id)
        authenticator = VirtualAuthenticator()
        user_id = _register_passkey(username, authenticator)

        results.append(_case("1. Valid device signature", "accepted", lambda: _valid_device(device_key, registration_id)))
        results.append(_case("2. Modified device signature", "rejected", lambda: _modified_device(device_key, registration_id)))
        results.append(_case("3. Replayed device challenge", "rejected", lambda: _replay_device(device_key, registration_id)))
        results.append(_case("4. Expired device challenge", "rejected", lambda: _expired_device(registration_id)))
        results.append(_case("5. Unknown device", "rejected", lambda: _unknown_device()))
        results.append(_case("6. Incorrect device public key", "rejected", lambda: _wrong_device_key(registration_id)))
        results.append(_case("7. Invalid WebAuthn challenge", "rejected", lambda: _bad_webauthn_challenge(username, authenticator, user_id)))
        results.append(_case("8. Incorrect WebAuthn origin", "rejected", lambda: _bad_origin(username, authenticator, user_id)))
        results.append(_case("9. Incorrect RP ID", "rejected", lambda: _bad_rp_id(username, authenticator, user_id)))
        results.append(_case("10. WebAuthn assertion without required UV", "rejected", lambda: _missing_uv(username, authenticator, user_id)))
        results.append(_case("11. Device authentication succeeds but WebAuthn fails", "no session", lambda: _device_only(device_key, registration_id, username, authenticator, user_id)))
        results.append(_case("12. WebAuthn succeeds but device authentication fails", "no session", lambda: _webauthn_only(registration_id, username, authenticator, user_id)))
    finally:
        _cleanup(username, registration_ids)
    passed = all(item["passed"] for item in results) and len(results) == 12
    return {
        "ok": True,
        "passed": passed,
        "summary": f"{sum(1 for item in results if item['passed'])} of {len(results)} verifier checks passed. These checks run the backend verification functions; they are not DT610 device measurements.",
        "results": results,
    }


def _case(name: str, expected: str, function) -> dict:
    try:
        actual, detail = function()
    except Exception as exc:
        actual, detail = "error", f"{type(exc).__name__}: {exc}"
    return {
        "name": name,
        "expected": expected,
        "actual": actual,
        "passed": actual == expected,
        "detail": detail,
    }


def _valid_device(key, registration_id: str) -> tuple[str, str]:
    challenge = create_device_challenge(registration_id)
    signature = _sign(key, b64url_decode(challenge["challenge"]))
    verify_device_challenge(challenge["challenge_id"], b64url_encode(signature))
    return "accepted", "Backend accepted a P-256 signature from the enrolled public key"


def _modified_device(key, registration_id: str) -> tuple[str, str]:
    challenge = create_device_challenge(registration_id)
    signature = bytearray(_sign(key, b64url_decode(challenge["challenge"])))
    signature[-1] ^= 0x01

    def submit() -> None:
        verify_device_challenge(challenge["challenge_id"], b64url_encode(bytes(signature)))

    return _expect_rejection(submit)


def _replay_device(key, registration_id: str) -> tuple[str, str]:
    challenge = create_device_challenge(registration_id)
    signature = b64url_encode(_sign(key, b64url_decode(challenge["challenge"])))
    verify_device_challenge(challenge["challenge_id"], signature)
    return _expect_rejection(lambda: verify_device_challenge(challenge["challenge_id"], signature))


def _expired_device(registration_id: str) -> tuple[str, str]:
    challenge_id = "expired-" + os.urandom(4).hex()
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO device_challenges(
                challenge_id, registration_id, challenge, created_at, expires_at, used_at
            ) VALUES(?, ?, ?, ?, ?, NULL)
            """,
            (challenge_id, registration_id, os.urandom(32), "2000-01-01T00:00:00+00:00", "2000-01-01T00:00:01+00:00"),
        )
    return _expect_rejection(lambda: verify_device_challenge(challenge_id, b64url_encode(b"\x30\x06\x02\x01\x01\x02\x01\x01")))


def _unknown_device() -> tuple[str, str]:
    return _expect_rejection(lambda: create_device_challenge("00000000-0000-0000-0000-000000000099"))


def _wrong_device_key(registration_id: str) -> tuple[str, str]:
    other = ec.generate_private_key(ec.SECP256R1())
    challenge = create_device_challenge(registration_id)
    signature = _sign(other, b64url_decode(challenge["challenge"]))
    return _expect_rejection(lambda: verify_device_challenge(challenge["challenge_id"], b64url_encode(signature)))


def _bad_webauthn_challenge(username: str, authenticator: VirtualAuthenticator, user_id: bytes) -> tuple[str, str]:
    options = create_authentication_options(username)
    request = json.loads(options["request_json"])
    assertion = authenticator.authentication(
        challenge=b64url_decode(request["challenge"]),
        rp_id=get_settings().rp_id,
        origin=get_settings().origin,
        user_id=user_id,
        challenge_override=os.urandom(32),
    )
    return _expect_rejection(lambda: finish_authentication(options["challenge_id"], assertion))


def _bad_origin(username: str, authenticator: VirtualAuthenticator, user_id: bytes) -> tuple[str, str]:
    options = create_authentication_options(username)
    request = json.loads(options["request_json"])
    assertion = authenticator.authentication(
        challenge=b64url_decode(request["challenge"]),
        rp_id=get_settings().rp_id,
        origin=get_settings().origin,
        user_id=user_id,
        origin_override="https://evil.invalid",
    )
    return _expect_rejection(lambda: finish_authentication(options["challenge_id"], assertion))


def _bad_rp_id(username: str, authenticator: VirtualAuthenticator, user_id: bytes) -> tuple[str, str]:
    options = create_authentication_options(username)
    request = json.loads(options["request_json"])
    assertion = authenticator.authentication(
        challenge=b64url_decode(request["challenge"]),
        rp_id=get_settings().rp_id,
        origin=get_settings().origin,
        user_id=user_id,
        rp_id_for_hash="wrong.example",
    )
    return _expect_rejection(lambda: finish_authentication(options["challenge_id"], assertion))


def _missing_uv(username: str, authenticator: VirtualAuthenticator, user_id: bytes) -> tuple[str, str]:
    options = create_authentication_options(username)
    request = json.loads(options["request_json"])
    assertion = authenticator.authentication(
        challenge=b64url_decode(request["challenge"]),
        rp_id=get_settings().rp_id,
        origin=get_settings().origin,
        user_id=user_id,
        uv=False,
    )
    return _expect_rejection(lambda: finish_authentication(options["challenge_id"], assertion))


def _device_only(device_key, registration_id: str, username: str, authenticator: VirtualAuthenticator, user_id: bytes) -> tuple[str, str]:
    started = start_transaction(registration_id, username)
    signature = _sign(device_key, b64url_decode(started["challenge"]))
    submit_device(started["transaction_id"], b64url_encode(signature))
    options = create_authentication_options(username)
    request = json.loads(options["request_json"])
    assertion = authenticator.authentication(
        challenge=b64url_decode(request["challenge"]),
        rp_id=get_settings().rp_id,
        origin=get_settings().origin,
        user_id=user_id,
    )
    assertion["response"]["signature"] = b64url_encode(b"\x00" * 64)
    try:
        submit_webauthn(started["transaction_id"], assertion)
        return "session created", "WebAuthn failure still created a session"
    except VerificationRejected:
        return _session_state(started["transaction_id"])


def _webauthn_only(registration_id: str, username: str, authenticator: VirtualAuthenticator, user_id: bytes) -> tuple[str, str]:
    standalone = create_authentication_options(username)
    request = json.loads(standalone["request_json"])
    assertion = authenticator.authentication(
        challenge=b64url_decode(request["challenge"]),
        rp_id=get_settings().rp_id,
        origin=get_settings().origin,
        user_id=user_id,
    )
    finish_authentication(standalone["challenge_id"], assertion)
    started = start_transaction(registration_id, username)
    other = ec.generate_private_key(ec.SECP256R1())
    wrong_signature = other.sign(b64url_decode(started["challenge"]), ec.ECDSA(hashes.SHA256()))
    try:
        submit_device(started["transaction_id"], b64url_encode(wrong_signature))
    except VerificationRejected:
        pass
    else:
        return "session created", "Bad device signature was accepted"
    try:
        submit_webauthn(started["transaction_id"], assertion)
    except VerificationRejected:
        state = _session_state(started["transaction_id"])
        if state[0] != "no session":
            return state
        return "no session", "Standalone WebAuthn verification succeeded and the integrated transaction still has no session"
    return "session created", "A valid WebAuthn assertion created a session after device authentication failed"


def _session_state(transaction_id: str) -> tuple[str, str]:
    conn = connect()
    try:
        row = conn.execute(
            "SELECT session_id FROM sessions WHERE transaction_id = ?",
            (transaction_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is not None:
        return "session created", "A session row exists"
    return "no session", "No session row exists for the transaction"


def _expect_rejection(function) -> tuple[str, str]:
    try:
        function()
    except VerificationRejected as exc:
        return "rejected", str(exc)
    return "accepted", "The verifier accepted input that should have been rejected"


def _enroll(username: str, spki: bytes) -> str:
    token = create_enrollment_token()["enrollment_token"]
    registered = register_device(
        {
            "enrollment_token": token,
            "public_key_spki": b64url_encode(spki),
            "fingerprint": fingerprint_hex(spki),
            "algorithm": "ECDSA P-256 SHA-256",
            "security_level": "SOFTWARE",
            "user_authentication_required": False,
            "private_key_exportable": False,
            "key_alias": "negtest",
            "device_info": {"manufacturer": "TEST", "model": "negative-suite", "username": username},
        }
    )
    return registered["registration_id"]


def _register_passkey(username: str, authenticator: VirtualAuthenticator) -> bytes:
    options = create_registration_options(username)
    request = json.loads(options["request_json"])
    user_id = b64url_decode(request["user"]["id"])
    credential = authenticator.registration(
        challenge=b64url_decode(request["challenge"]),
        rp_id=get_settings().rp_id,
        origin=get_settings().origin,
    )
    finish_registration(options["challenge_id"], credential)
    return user_id


def _sign(key, challenge: bytes) -> bytes:
    return key.sign(challenge, ec.ECDSA(hashes.SHA256()))


def _cleanup(username: str, registration_ids: list[str]) -> None:
    with transaction() as conn:
        conn.execute("DELETE FROM webauthn_credentials WHERE username = ?", (username,))
        conn.execute("DELETE FROM webauthn_users WHERE username = ?", (username,))
        conn.execute("DELETE FROM webauthn_challenges WHERE username = ?", (username,))
        conn.execute("DELETE FROM webauthn_events WHERE username = ?", (username,))
        conn.execute("DELETE FROM auth_transactions WHERE username = ?", (username,))
        conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
        for registration_id in registration_ids:
            conn.execute("DELETE FROM attempts WHERE registration_id = ?", (registration_id,))
            conn.execute("DELETE FROM device_verify_events WHERE registration_id = ?", (registration_id,))
            conn.execute("DELETE FROM device_challenges WHERE registration_id = ?", (registration_id,))
            conn.execute("DELETE FROM devices WHERE registration_id = ?", (registration_id,))


def store_negative_run(payload: dict) -> None:
    with transaction() as conn:
        conn.execute(
            "INSERT INTO negative_runs(ran_at, passed, results_json) VALUES(?, ?, ?)",
            (utcnow(), 1 if payload["passed"] else 0, json.dumps(payload["results"])),
        )
