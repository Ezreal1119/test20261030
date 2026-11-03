from __future__ import annotations

import json
import secrets
import uuid

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.helpers.structs import CredentialDeviceType

from app.config import get_settings
from app.db import connect, expires_in, get_setting, set_setting, transaction, utcnow
from app.errors import VerificationRejected
from app.services.encoding import b64url_decode, b64url_encode, ecdsa_signature_to_der


def publish_assetlinks(package_name: str, fingerprints: list[str]) -> dict:
    normalized = [_normalize_fingerprint(item) for item in fingerprints]
    if not normalized:
        raise VerificationRejected("At least one certificate fingerprint is required")
    if not package_name or ".." in package_name or " " in package_name:
        raise VerificationRejected("Package name is invalid")
    set_setting("package_name", package_name)
    set_setting("fingerprints", json.dumps(normalized))
    return {
        "ok": True,
        "message": "Digital Asset Links fingerprint saved. Serve /.well-known/assetlinks.json from the RP ID origin.",
        "package_name": package_name,
        "sha256_cert_fingerprints": normalized,
    }


def assetlinks_document() -> list[dict]:
    settings = get_settings()
    package_name = get_setting("package_name", settings.package_name)
    return [
        {
            "relation": [
                "delegate_permission/common.handle_all_urls",
                "delegate_permission/common.get_login_creds",
            ],
            "target": {
                "namespace": "android_app",
                "package_name": package_name,
                "sha256_cert_fingerprints": fingerprints(),
            },
        }
    ]


def fingerprints() -> list[str]:
    raw = get_setting("fingerprints", "[]")
    try:
        values = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [str(item) for item in values] if isinstance(values, list) else []


def expected_origins() -> list[str]:
    settings = get_settings()
    origins: list[str] = []
    for origin in (settings.origin, f"https://{settings.rp_id}"):
        if origin not in origins:
            origins.append(origin)
    for fingerprint in fingerprints():
        digest = bytes.fromhex(fingerprint.replace(":", ""))
        origins.append("android:apk-key-hash:" + b64url_encode(digest))
    return origins


def create_registration_options(username: str, registration_id: str | None = None) -> dict:
    _check_username(username)
    settings = get_settings()
    user_id = _ensure_user(username)
    exclude = [
        PublicKeyCredentialDescriptor(id=row["credential_id"])
        for row in _credentials_for(username)
    ]
    options = generate_registration_options(
        rp_id=settings.rp_id,
        rp_name=settings.rp_name,
        user_name=username,
        user_id=user_id,
        user_display_name=username,
        timeout=settings.challenge_ttl_seconds * 1000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=exclude,
        supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
    )
    challenge_id = _store_challenge(options.challenge, "registration", username, None)
    return {"ok": True, "challenge_id": challenge_id, "request_json": options_to_json(options), "registration_id": registration_id}


def finish_registration(challenge_id: str, credential_json: str | dict, registration_id: str | None = None) -> dict:
    credential = _load_credential_json(credential_json)
    row = _claim_webauthn_challenge(challenge_id, "registration")
    settings = get_settings()
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=bytes(row["challenge"]),
            expected_rp_id=settings.rp_id,
            expected_origin=expected_origins(),
            require_user_presence=True,
            require_user_verification=True,
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
        )
    except (InvalidRegistrationResponse, Exception) as exc:
        message = str(exc)
        _event(row["username"], None, "registration", False, None, None, None, None, message, None)
        if isinstance(exc, (InvalidRegistrationResponse, VerificationRejected)):
            raise VerificationRejected(message) from exc
        raise VerificationRejected("WebAuthn registration was rejected") from exc
    if not verified.user_verified:
        raise VerificationRejected("User verification is required but was not performed")
    credential_id_b64 = b64url_encode(verified.credential_id)
    backed_up = bool(verified.credential_backed_up)
    multi_device = verified.credential_device_type == CredentialDeviceType.MULTI_DEVICE
    now = utcnow()
    with transaction() as conn:
        existing = conn.execute(
            "SELECT credential_id_b64 FROM webauthn_credentials WHERE credential_id_b64 = ?",
            (credential_id_b64,),
        ).fetchone()
        if existing is not None:
            raise VerificationRejected("This Passkey is already registered")
        conn.execute(
            """
            INSERT INTO webauthn_credentials(
                credential_id_b64, credential_id, username, public_key, sign_count, aaguid,
                backup_eligible, backup_state, device_type, user_verified, registration_id,
                created_at, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                credential_id_b64,
                verified.credential_id,
                row["username"],
                verified.credential_public_key,
                verified.sign_count,
                verified.aaguid,
                1 if multi_device else 0,
                1 if backed_up else 0,
                verified.credential_device_type.value,
                1,
                registration_id,
                now,
                now,
            ),
        )
    summary = _property_summary(
        "Passkey registration verified.",
        user_verified=True,
        backup_eligible=multi_device,
        backup_state=backed_up,
        device_type=verified.credential_device_type.value,
    )
    _event(
        row["username"],
        credential_id_b64,
        "registration",
        True,
        True,
        multi_device,
        backed_up,
        verified.credential_device_type.value,
        summary,
        None,
    )
    return {
        "ok": True,
        "summary": summary,
        "user_verified": True,
        "backup_eligible": multi_device,
        "backup_state": backed_up,
        "device_type": verified.credential_device_type.value,
    }


def create_authentication_options(username: str, transaction_id: str | None = None) -> dict:
    _check_username(username)
    creds = _credentials_for(username)
    if not creds:
        raise VerificationRejected("Register a Passkey for this username before authentication")
    settings = get_settings()
    options = generate_authentication_options(
        rp_id=settings.rp_id,
        timeout=settings.challenge_ttl_seconds * 1000,
        allow_credentials=[PublicKeyCredentialDescriptor(id=bytes(row["credential_id"])) for row in creds],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    challenge_id = _store_challenge(options.challenge, "authentication", username, transaction_id)
    return {"ok": True, "challenge_id": challenge_id, "request_json": options_to_json(options)}


def finish_authentication(challenge_id: str, credential_json: str | dict, transaction_id: str | None = None) -> dict:
    credential = _normalize_assertion(_load_credential_json(credential_json))
    row = _claim_webauthn_challenge(challenge_id, "authentication")
    return _verify_claimed_assertion(row, credential, transaction_id)


def credential_summary(username: str) -> dict:
    _check_username(username)
    rows = _credentials_for(username)
    if not rows:
        return {
            "ok": True,
            "summary": "NOT TESTED\nNo Passkey is registered for this username.",
            "credentials": [],
        }
    lines = [
        "Properties below come from the last verified registration or authentication.",
        "BE = 1 means the credential may be a synced Passkey. This service does not classify it as device-bound.",
    ]
    credentials = []
    for row in rows:
        item = {
            "credential_id": row["credential_id_b64"],
            "backup_eligible": bool(row["backup_eligible"]),
            "backup_state": bool(row["backup_state"]),
            "device_type": row["device_type"],
            "user_verified": bool(row["user_verified"]),
            "sign_count": row["sign_count"],
            "aaguid": row["aaguid"],
        }
        credentials.append(item)
        lines.append(
            f"UV={item['user_verified']} UP is required by the verifier. "
            f"BE={item['backup_eligible']} BS={item['backup_state']} type={item['device_type']} "
            f"signCount={item['sign_count']}"
        )
    return {"ok": True, "summary": "\n".join(lines), "credentials": credentials}


def _verify_claimed_assertion(row: dict, credential: dict, transaction_id: str | None) -> dict:
    credential_id = str(credential.get("id", ""))
    stored = _credential(credential_id)
    if stored is None or stored["username"] != row["username"]:
        _event(row["username"], credential_id, "authentication", False, None, None, None, None, "Unknown credential", transaction_id)
        raise VerificationRejected("WebAuthn credential is not registered for this user")
    handle = credential.get("response", {}).get("userHandle")
    if isinstance(handle, str) and handle:
        user = _user(row["username"])
        if user is None or b64url_decode(handle) != bytes(user["user_id"]):
            raise VerificationRejected("User handle does not match the registered user")
    settings = get_settings()
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=bytes(row["challenge"]),
            expected_rp_id=settings.rp_id,
            expected_origin=expected_origins(),
            credential_public_key=bytes(stored["public_key"]),
            credential_current_sign_count=int(stored["sign_count"]),
            require_user_verification=True,
        )
    except InvalidAuthenticationResponse as exc:
        _event(row["username"], credential_id, "authentication", False, None, None, None, None, str(exc), transaction_id)
        raise VerificationRejected(str(exc)) from exc
    if not verified.user_verified:
        raise VerificationRejected("User verification flag was not set")
    multi_device = verified.credential_device_type == CredentialDeviceType.MULTI_DEVICE
    backed_up = bool(verified.credential_backed_up)
    with transaction() as conn:
        conn.execute(
            """
            UPDATE webauthn_credentials
            SET sign_count = ?, backup_eligible = ?, backup_state = ?, device_type = ?,
                user_verified = 1, updated_at = ?
            WHERE credential_id_b64 = ?
            """,
            (
                verified.new_sign_count,
                1 if multi_device else 0,
                1 if backed_up else 0,
                verified.credential_device_type.value,
                utcnow(),
                credential_id,
            ),
        )
    summary = _property_summary(
        "WebAuthn authentication verified. Challenge, RP ID hash, origin, signature, and user verification were checked.",
        user_verified=True,
        backup_eligible=multi_device,
        backup_state=backed_up,
        device_type=verified.credential_device_type.value,
    )
    _event(
        row["username"],
        credential_id,
        "authentication",
        True,
        True,
        multi_device,
        backed_up,
        verified.credential_device_type.value,
        summary,
        transaction_id,
    )
    return {
        "ok": True,
        "summary": summary,
        "user_verified": True,
        "backup_eligible": multi_device,
        "backup_state": backed_up,
        "device_type": verified.credential_device_type.value,
        "credential_id": credential_id,
    }


def _store_challenge(challenge: bytes, purpose: str, username: str, transaction_id: str | None) -> str:
    challenge_id = str(uuid.uuid4())
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO webauthn_challenges(
                challenge_id, challenge, purpose, username, transaction_id, created_at, expires_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                challenge_id,
                challenge,
                purpose,
                username,
                transaction_id,
                utcnow(),
                expires_in(get_settings().challenge_ttl_seconds),
            ),
        )
    return challenge_id


def _claim_webauthn_challenge(challenge_id: str, purpose: str) -> dict:
    with transaction() as conn:
        row = conn.execute(
            "SELECT * FROM webauthn_challenges WHERE challenge_id = ?",
            (challenge_id,),
        ).fetchone()
        if row is None or row["purpose"] != purpose:
            raise VerificationRejected("WebAuthn challenge was not found")
        if row["used_at"] is not None:
            raise VerificationRejected("Replayed WebAuthn challenge")
        if row["expires_at"] <= utcnow():
            raise VerificationRejected("Expired WebAuthn challenge")
        updated = conn.execute(
            "UPDATE webauthn_challenges SET used_at = ? WHERE challenge_id = ? AND used_at IS NULL",
            (utcnow(), challenge_id),
        )
        if updated.rowcount != 1:
            raise VerificationRejected("Replayed WebAuthn challenge")
        return dict(row)


def _ensure_user(username: str) -> bytes:
    existing = _user(username)
    if existing is not None:
        return bytes(existing["user_id"])
    user_id = secrets.token_bytes(32)
    with transaction() as conn:
        conn.execute(
            "INSERT INTO webauthn_users(username, user_id, display_name, created_at) VALUES(?, ?, ?, ?)",
            (username, user_id, username, utcnow()),
        )
    return user_id


def _user(username: str) -> dict | None:
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM webauthn_users WHERE username = ?", (username,)).fetchone()
        return None if row is None else dict(row)
    finally:
        conn.close()


def _credentials_for(username: str) -> list[dict]:
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE username = ? ORDER BY created_at",
            (username,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _credential(credential_id_b64: str) -> dict | None:
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE credential_id_b64 = ?",
            (credential_id_b64,),
        ).fetchone()
        return None if row is None else dict(row)
    finally:
        conn.close()


def _event(
    username: str | None,
    credential_id: str | None,
    purpose: str,
    accepted: bool,
    user_verified: bool | None,
    backup_eligible: bool | None,
    backup_state: bool | None,
    device_type: str | None,
    reason: str,
    transaction_id: str | None,
) -> None:
    settings = get_settings()
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO webauthn_events(
                username, credential_id_b64, purpose, accepted, user_verified, backup_eligible,
                backup_state, device_type, origin, rp_id, reason, transaction_id, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                credential_id,
                purpose,
                1 if accepted else 0,
                None if user_verified is None else int(user_verified),
                None if backup_eligible is None else int(backup_eligible),
                None if backup_state is None else int(backup_state),
                device_type,
                settings.origin,
                settings.rp_id,
                reason[:500],
                transaction_id,
                utcnow(),
            ),
        )


def _load_credential_json(value: str | dict) -> dict:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise VerificationRejected("Credential JSON is malformed") from exc
    if not isinstance(value, dict):
        raise VerificationRejected("Credential JSON must be an object")
    attachment = value.get("authenticatorAttachment")
    if attachment not in (None, "platform", "cross-platform"):
        value = dict(value)
        value.pop("authenticatorAttachment", None)
    return value


def _normalize_assertion(credential: dict) -> dict:
    response = credential.get("response")
    if not isinstance(response, dict) or "signature" not in response:
        return credential
    try:
        signature = b64url_decode(str(response["signature"]))
    except Exception as exc:
        raise VerificationRejected("WebAuthn signature encoding is invalid") from exc
    normalized = dict(credential)
    updated = dict(response)
    updated["signature"] = b64url_encode(ecdsa_signature_to_der(signature))
    normalized["response"] = updated
    return normalized


def _property_summary(prefix: str, user_verified: bool, backup_eligible: bool, backup_state: bool, device_type: str) -> str:
    bound = "The backup eligibility flag is clear, which is consistent with a credential that the authenticator did not mark as copyable."
    synced = "Backup eligibility is set. This credential may be a synced Passkey and is not classified as device-bound."
    return "\n".join(
        [
            prefix,
            f"UP: required and checked by the verifier. UV: {str(user_verified).lower()}.",
            f"BE: {str(backup_eligible).lower()}. BS: {str(backup_state).lower()}. Credential type: {device_type}.",
            synced if backup_eligible else bound,
            "A verified UV flag is evidence of a phishing-resistant ceremony on this relying party. It does not by itself prove the customer's enterprise identity-provider policy.",
        ]
    )


def _normalize_fingerprint(value: str) -> str:
    compact = value.replace(":", "").replace(" ", "").upper()
    if len(compact) != 64 or any(character not in "0123456789ABCDEF" for character in compact):
        raise VerificationRejected("SHA-256 certificate fingerprint must be 32 bytes")
    return ":".join(compact[index : index + 2] for index in range(0, 64, 2))


def _check_username(username: str) -> None:
    if not username or len(username) > 64:
        raise VerificationRejected("Username is missing or too long")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@+-")
    if any(character not in allowed for character in username):
        raise VerificationRejected("Username contains unsupported characters")
