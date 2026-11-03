import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app.services.attestation import ATTESTATION_OID, build_key_description, verify_attestation
from app.services.negative_tests import run_negative_tests
from app.services.reporting import assess_compliance, build_report


def test_negative_suite_uses_real_verification(ctx):
    result = run_negative_tests()
    failures = [item for item in result["results"] if not item["passed"]]
    assert result["passed"], failures
    assert len(result["results"]) == 12


def test_empty_report_does_not_invent_results(ctx):
    report = build_report()
    statuses = {item["id"]: item["status"] for item in report["compliance"]}
    assert statuses == {
        "A": "NOT VERIFIED",
        "B": "NOT VERIFIED",
        "C": "NOT VERIFIED",
        "D": "NOT VERIFIED",
        "E": "NOT VERIFIED",
        "F": "NOT VERIFIED",
    }
    assert report["device_authentication"]["status"] == "NOT TESTED"
    assert report["performance"]["count"] == 0
    assert "reference implementation" in " ".join(report["limitations"]).lower()


def test_average_below_target_is_not_enough_for_full_verification():
    facts = {
        "accepted_signatures": 2,
        "exportable": False,
        "attestation_verified": False,
        "attestation_level": None,
        "webauthn_uv_successes": 2,
        "webauthn_registrations": 1,
        "backup_eligible": True,
        "integrated_sessions": 1,
        "timing_attempts": 2,
        "timing_successes": 2,
        "timing_failures": 0,
        "over_target": 0,
        "timer_discrepancies": 0,
        "max_success_ms": 4000,
    }
    statuses = {item["id"]: item["status"] for item in assess_compliance(facts)}
    assert statuses["A"] == "PARTIALLY VERIFIED"
    assert statuses["E"] == "PARTIALLY VERIFIED"
    assert statuses["F"] == "NOT VERIFIED"
    assert statuses["C"] == "VERIFIED"


def test_attempt_over_twenty_seconds_is_not_verified():
    facts = {
        "accepted_signatures": 1,
        "exportable": False,
        "attestation_verified": True,
        "attestation_level": "TRUSTED_ENVIRONMENT",
        "webauthn_uv_successes": 1,
        "webauthn_registrations": 1,
        "backup_eligible": False,
        "integrated_sessions": 1,
        "timing_attempts": 10,
        "timing_successes": 10,
        "timing_failures": 0,
        "over_target": 1,
        "timer_discrepancies": 0,
        "max_success_ms": 21000,
    }
    statuses = {item["id"]: item["status"] for item in assess_compliance(facts)}
    assert statuses["E"] == "NOT VERIFIED"
    assert statuses["A"] == "VERIFIED"
    assert statuses["B"] == "PARTIALLY VERIFIED"


def test_attestation_accepts_only_the_pinned_chain():
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    root_key = ec.generate_private_key(ec.SECP256R1())
    challenge = b"server-challenge-value-32b!!!!!"
    leaf, root = _chain(leaf_key, root_key, challenge, keymaster_level=1)
    spki = leaf_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verified = verify_attestation([leaf, root], challenge, spki, roots=[root])
    assert verified["verified"] is True
    assert verified["security_level"] == "TRUSTED_ENVIRONMENT"

    wrong_challenge = verify_attestation([leaf, root], b"other-challenge", spki, roots=[root])
    assert wrong_challenge["verified"] is False
    assert "Hardware-backed attestation not verified." in wrong_challenge["status"]

    software_leaf, software_root = _chain(leaf_key, root_key, challenge, keymaster_level=0)
    software = verify_attestation([software_leaf, software_root], challenge, spki, roots=[software_root])
    assert software["verified"] is False

    untrusted = verify_attestation([leaf, root], challenge, spki, roots=[])
    assert untrusted["verified"] is False


def test_api_rejects_a_fabricated_success_and_stores_the_suite(ctx):
    from app.main import create_app

    with TestClient(create_app()) as client:
        denied = client.post("/api/security/negative-tests")
        assert denied.status_code == 401
        headers = {"X-Admin-Token": "test-admin-token"}
        suite = client.post("/api/security/negative-tests", headers=headers)
        assert suite.status_code == 200, suite.text
        assert suite.json()["passed"] is True
        fake = client.post(
            "/api/auth/attempts",
            headers=headers,
            json={
                "transaction_id": "",
                "total_ms": 1000,
                "device_ms": 400,
                "webauthn_ms": 400,
                "session_ms": 200,
                "device_result": "PASS",
                "webauthn_result": "PASS",
                "session_result": "PASS",
                "network_type": "WIFI",
                "failure_reason": "",
                "device_info": {},
            },
        )
        assert fake.status_code == 400
        report = client.get("/api/reports/evidence.json", headers=headers)
        assert report.status_code == 200
        body = report.json()
        assert len(body["negative_tests"]["results"]) == 12
        assert body["integrated"]["status"] == "NOT TESTED"
        pdf = client.get("/api/reports/evidence.pdf", headers=headers)
        assert pdf.status_code == 200
        assert pdf.content.startswith(b"%PDF")


def _chain(leaf_key, root_key, challenge: bytes, keymaster_level: int):
    now = datetime.now(timezone.utc)
    root_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Attestation Root")])
    leaf_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Leaf")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.UnrecognizedExtension(ATTESTATION_OID, build_key_description(challenge, 1, keymaster_level)),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return leaf, root


def test_integrated_journey_issues_one_session(ctx):
    from app.services.device_auth import create_enrollment_token, register_device
    from app.services.encoding import b64url_decode, b64url_encode, fingerprint_hex
    from app.services.transactions import read_session, start_transaction, submit_device, submit_webauthn
    from app.services.virtual_authenticator import VirtualAuthenticator
    from app.services.webauthn_service import create_registration_options, finish_registration
    from app.config import get_settings

    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    token = create_enrollment_token()["enrollment_token"]
    registered = register_device(
        {
            "enrollment_token": token,
            "public_key_spki": b64url_encode(spki),
            "fingerprint": fingerprint_hex(spki),
            "security_level": "SOFTWARE",
            "private_key_exportable": False,
            "user_authentication_required": False,
            "key_alias": "test",
            "device_info": {"manufacturer": "UROVO", "model": "DT610 Pro"},
        }
    )
    authenticator = VirtualAuthenticator()
    options = create_registration_options("operator")
    request = json.loads(options["request_json"])
    user_id = b64url_decode(request["user"]["id"])
    finish_registration(
        options["challenge_id"],
        authenticator.registration(
            challenge=b64url_decode(request["challenge"]),
            rp_id=get_settings().rp_id,
            origin=get_settings().origin,
        ),
    )
    started = start_transaction(registered["registration_id"], "operator")
    signature = key.sign(b64url_decode(started["challenge"]), ec.ECDSA(hashes.SHA256()))
    device = submit_device(started["transaction_id"], b64url_encode(signature))
    web_request = json.loads(device["request_json"])
    completed = submit_webauthn(
        started["transaction_id"],
        authenticator.authentication(
            challenge=b64url_decode(web_request["challenge"]),
            rp_id=get_settings().rp_id,
            origin=get_settings().origin,
            user_id=user_id,
        ),
    )
    session = read_session(completed["session_token"])
    assert session["active"] is True
    from app.services.transactions import record_attempt

    saved = record_attempt(
        {
            "transaction_id": started["transaction_id"],
            "registration_id": registered["registration_id"],
            "total_ms": 1800,
            "device_ms": 300,
            "webauthn_ms": 1200,
            "session_ms": 300,
            "device_result": "PASS",
            "webauthn_result": "PASS",
            "session_result": "PASS",
            "network_type": "WIFI",
            "failure_reason": "",
            "device_info": {"manufacturer": "UROVO", "model": "DT610 Pro", "android_version": "15"},
        }
    )
    assert saved["corroborated"] is True
    report = build_report()
    assert report["integrated"]["sessions"] == 1
    assert report["environment"]["device_model"] == "DT610 Pro"
