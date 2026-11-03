from __future__ import annotations

import json
import math
from datetime import datetime, timezone

from fpdf import FPDF

from app.config import BACKEND_VERSION, get_settings, rp_is_configured
from app.db import connect, utcnow
from app.services.webauthn_service import fingerprints

TITLE = "UROVO DT610 Pro – Device-Bound Authentication and Phishing-Resistant MFA Verification Report"
TARGET_MS = 20_000


def build_report() -> dict:
    settings = get_settings()
    devices = _rows("SELECT * FROM devices ORDER BY created_at")
    events = _rows("SELECT * FROM webauthn_events ORDER BY id")
    attempts = _rows("SELECT * FROM attempts ORDER BY id")
    sessions = _rows("SELECT session_id, transaction_id, username, created_at, expires_at FROM sessions")
    completed = _rows("SELECT * FROM auth_transactions WHERE state = 'completed' ORDER BY completed_at")
    negative = _latest_negative_run()
    device_info = _latest_device_info(devices, attempts)
    corroborated = [row for row in attempts if row["corroborated"]]
    performance = _performance(corroborated)
    report = {
        "title": TITLE,
        "generated_at": utcnow(),
        "reference_implementation": True,
        "limitations": _limitations(),
        "environment": {
            "device_manufacturer": device_info.get("manufacturer", "NOT TESTED"),
            "device_model": device_info.get("model", "NOT TESTED"),
            "android_version": device_info.get("android_version", "NOT TESTED"),
            "sdk_int": device_info.get("sdk_int", "NOT TESTED"),
            "build_number": device_info.get("build_number", "NOT TESTED"),
            "security_patch": device_info.get("security_patch", "NOT TESTED"),
            "build_fingerprint": device_info.get("fingerprint", "NOT TESTED"),
            "application_version": device_info.get("app_version", "NOT TESTED"),
            "backend_version": BACKEND_VERSION,
            "network_environment": _latest_network(attempts),
            "test_date": datetime.now(timezone.utc).date().isoformat(),
            "rp_id": settings.rp_id,
            "origin": settings.origin,
            "rp_configured": rp_is_configured(settings),
            "asset_link_fingerprints_configured": bool(fingerprints()),
        },
        "device_authentication": {
            "status": "NOT TESTED" if not devices else "RECORDED",
            "devices": [_device_view(row) for row in devices],
            "accepted_signatures": _count("SELECT COUNT(*) AS n FROM device_verify_events WHERE accepted = 1"),
            "rejected_signatures": _count("SELECT COUNT(*) AS n FROM device_verify_events WHERE accepted = 0"),
        },
        "webauthn": {
            "status": "NOT TESTED" if not events else "RECORDED",
            "registrations_verified": sum(1 for row in events if row["purpose"] == "registration" and row["accepted"]),
            "authentications_verified": sum(1 for row in events if row["purpose"] == "authentication" and row["accepted"]),
            "user_verification_successes": sum(
                1 for row in events if row["purpose"] == "authentication" and row["accepted"] and row["user_verified"]
            ),
            "rp_id": settings.rp_id,
            "origin": settings.origin,
            "credentials": [_credential_view(row) for row in _rows("SELECT * FROM webauthn_credentials ORDER BY created_at")],
        },
        "integrated": {
            "status": "NOT TESTED" if not completed else "RECORDED",
            "completed_transactions": len(completed),
            "sessions": len(sessions),
            "latest": _latest_integrated(completed, corroborated),
        },
        "negative_tests": negative or {"status": "NOT TESTED", "results": []},
        "performance": performance,
        "attempts": [_attempt_view(row, index + 1) for index, row in enumerate(attempts)],
    }
    report["compliance"] = assess_compliance(_facts(report))
    return report


def assess_compliance(facts: dict) -> list[dict]:
    return [
        _device_bound(facts),
        _certificate_based(facts),
        _phishing_resistant(facts),
        _integrated(facts),
        _sign_on_time(facts),
        {
            "id": "F",
            "item": "Customer enterprise IdP integration",
            "status": "NOT VERIFIED",
            "rationale": "This reference implementation does not connect to the customer's identity provider, production application, or operational environment.",
        },
    ]


def render_pdf(report: dict) -> bytes:
    pdf = _Pdf()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.multi_cell(0, 8, _safe(report["title"]))
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, _safe("Generated: " + report["generated_at"]))
    pdf.ln(1)
    _section(pdf, "1. Test environment")
    env = report["environment"]
    _body(
        pdf,
        "\n".join(
            [
                f"Device model: {env['device_manufacturer']} {env['device_model']}",
                f"Android version: {env['android_version']} (API {env['sdk_int']})",
                f"Build number: {env['build_number']}",
                f"Security patch: {env['security_patch']}",
                f"Build fingerprint: {env['build_fingerprint']}",
                f"Application version: {env['application_version']}",
                f"Backend version: {env['backend_version']}",
                f"Network environment: {env['network_environment']}",
                f"Test date: {env['test_date']}",
                f"RP ID: {env['rp_id']}",
                f"Origin: {env['origin']}",
            ]
        ),
    )
    _section(pdf, "2. Device-bound authentication")
    device = report["device_authentication"]
    if not device["devices"]:
        _body(pdf, "NOT TESTED. No device public key has been registered.")
    else:
        for item in device["devices"]:
            _body(
                pdf,
                "\n".join(
                    [
                        f"Registration: {item['registration_id']}",
                        f"Algorithm: {item['algorithm']}",
                        f"Key security level reported by the device: {item['security_level']}",
                        f"Public key fingerprint: {item['fingerprint']}",
                        f"Private key exportable as reported by the device: {item['private_key_exportable']}",
                        f"Challenge-response acceptances recorded for all devices: {device['accepted_signatures']}",
                        f"Attestation: {item['attestation_status']}",
                    ]
                ),
            )
    _section(pdf, "3. WebAuthn authentication")
    webauthn = report["webauthn"]
    if webauthn["status"] == "NOT TESTED":
        _body(pdf, "NOT TESTED. No WebAuthn ceremony has been verified.")
    else:
        _body(
            pdf,
            "\n".join(
                [
                    f"Passkey registrations verified: {webauthn['registrations_verified']}",
                    f"Passkey authentications verified: {webauthn['authentications_verified']}",
                    f"User verification successes: {webauthn['user_verification_successes']}",
                    f"RP ID checked by the verifier: {webauthn['rp_id']}",
                    f"Origin allow-list includes: {webauthn['origin']} and configured Android apk-key-hash origins.",
                ]
            ),
        )
        if not webauthn["credentials"]:
            _body(pdf, "No credential properties are stored.")
        for item in webauthn["credentials"]:
            _body(
                pdf,
                "\n".join(
                    [
                        f"Credential type: {item['device_type']}",
                        f"UV: {item['user_verified']}  BE: {item['backup_eligible']}  BS: {item['backup_state']}",
                        "BE true means the authenticator marked the credential as backup-eligible. It is not classified as device-bound.",
                    ]
                ),
            )
    _section(pdf, "4. Integrated authentication")
    integrated = report["integrated"]
    if integrated["status"] == "NOT TESTED":
        _body(pdf, "NOT TESTED. No transaction has completed both factors and created a session.")
    else:
        latest = integrated["latest"] or {}
        _body(
            pdf,
            "\n".join(
                [
                    f"Completed transactions: {integrated['completed_transactions']}",
                    f"Sessions issued: {integrated['sessions']}",
                    f"Device authentication result: {latest.get('device_result', 'NOT TESTED')}",
                    f"WebAuthn result: {latest.get('webauthn_result', 'NOT TESTED')}",
                    f"Backend session result: {latest.get('session_result', 'NOT TESTED')}",
                    f"Complete authentication duration: {latest.get('total_ms', 'NOT TESTED')} ms",
                ]
            ),
        )
    _section(pdf, "5. Security negative tests")
    _body(
        pdf,
        "These rows come from the backend verification suite. They are not measurements taken on the handset. A handset check appears in the server audit only when that handset called the verifier.",
    )
    negative = report["negative_tests"]
    if negative.get("status") == "NOT TESTED" or not negative.get("results"):
        _body(pdf, "NOT TESTED. The server verifier suite has not been run.")
    else:
        for item in negative["results"]:
            _body(
                pdf,
                f"{'PASS' if item.get('passed') else 'FAIL'} | {item.get('name')} | expected {item.get('expected')} | actual {item.get('actual')}",
            )
    _section(pdf, "6. Performance results")
    performance = report["performance"]
    if performance["count"] == 0:
        _body(pdf, "NOT TESTED. No corroborated complete-authentication attempts are stored.")
    else:
        _body(
            pdf,
            "\n".join(
                [
                    f"Attempts: {performance['count']}",
                    f"Minimum: {performance['minimum_ms']} ms",
                    f"Maximum: {performance['maximum_ms']} ms",
                    f"Average: {performance['average_ms']} ms",
                    f"P95: {performance['p95_ms'] if performance['p95_ms'] is not None else 'not calculated'}",
                    performance["p95_note"],
                    f"Attempts exceeding 20 seconds: {performance['over_target']}",
                    f"Success rate: {performance['success_rate']}",
                    "The acceptance measurement is the device monotonic timer. The server window is stored beside it and is not a substitute.",
                ]
            ),
        )
        for item in report["attempts"]:
            if not item["corroborated"]:
                continue
            _body(
                pdf,
                f"Attempt {item['attempt_number']} at {item['recorded_at']}: {item['total_ms']} ms, device {item['device_result']}, WebAuthn {item['webauthn_result']}, session {item['session_result']}, network {item['network_type']}",
            )
    _section(pdf, "7. Tender compliance assessment")
    for item in report["compliance"]:
        _body(pdf, f"{item['id']}. {item['item']}: {item['status']}\n{item['rationale']}")
    _section(pdf, "Limitations")
    _body(pdf, "\n".join(report["limitations"]))
    return bytes(pdf.output())


def list_attempts(registration_id: str | None) -> dict:
    rows = _rows("SELECT * FROM attempts ORDER BY id")
    if registration_id:
        rows = [row for row in rows if row["registration_id"] == registration_id]
    corroborated = [row for row in rows if row["corroborated"]]
    return {
        "ok": True,
        "stats": _performance(corroborated),
        "attempts": [_attempt_view(row, index + 1) for index, row in enumerate(rows)],
    }


def _facts(report: dict) -> dict:
    devices = report["device_authentication"]["devices"]
    successes = [row for row in report["attempts"] if row["corroborated"] and row["session_result"] == "PASS"]
    included = [row for row in report["attempts"] if row["corroborated"]]
    return {
        "accepted_signatures": report["device_authentication"]["accepted_signatures"],
        "exportable": any(item["private_key_exportable"] for item in devices),
        "attestation_verified": any(str(item["attestation_status"]).startswith("Verified.") for item in devices),
        "attestation_level": next(
            (item["attestation_level"] for item in devices if str(item["attestation_status"]).startswith("Verified.")),
            None,
        ),
        "webauthn_uv_successes": report["webauthn"]["user_verification_successes"],
        "webauthn_registrations": report["webauthn"]["registrations_verified"],
        "backup_eligible": any(item["backup_eligible"] for item in report["webauthn"]["credentials"]),
        "integrated_sessions": report["integrated"]["sessions"],
        "timing_attempts": len(included),
        "timing_successes": len(successes),
        "timing_failures": len(included) - len(successes),
        "over_target": sum(1 for row in included if row["total_ms"] > TARGET_MS),
        "timer_discrepancies": sum(1 for row in included if row["timer_discrepancy"]),
        "max_success_ms": max((row["total_ms"] for row in successes), default=None),
    }


def _device_bound(facts: dict) -> dict:
    if facts["accepted_signatures"] < 1:
        return _item("A", "Device-bound authentication", "NOT VERIFIED", "No server-verified device challenge-response is stored.")
    if facts["exportable"]:
        return _item("A", "Device-bound authentication", "NOT VERIFIED", "A registered key was reported as exportable through standard Android APIs.")
    if facts["attestation_verified"] and facts["attestation_level"] in {"TRUSTED_ENVIRONMENT", "STRONGBOX"}:
        return _item(
            "A",
            "Device-bound authentication",
            "VERIFIED",
            "A non-exportable P-256 key signed a server challenge and the attestation chain verified at "
            + str(facts["attestation_level"])
            + ".",
        )
    return _item(
        "A",
        "Device-bound authentication",
        "PARTIALLY VERIFIED",
        "The backend verified a challenge-response signature for a key reported as non-exportable. Hardware backing was not established by a trusted attestation chain.",
    )


def _certificate_based(facts: dict) -> dict:
    if facts["attestation_verified"]:
        return _item(
            "B",
            "Certificate-based authentication",
            "PARTIALLY VERIFIED",
            "Key attestation certificates were verified. This is not a customer PKI client-certificate sign-on.",
        )
    return _item(
        "B",
        "Certificate-based authentication",
        "NOT VERIFIED",
        "No attestation chain has been verified against a pinned hardware attestation root.",
    )


def _phishing_resistant(facts: dict) -> dict:
    if facts["webauthn_uv_successes"] >= 1:
        extra = " At least one stored credential is backup-eligible and is not classified as device-bound." if facts["backup_eligible"] else ""
        return _item(
            "C",
            "Phishing-resistant MFA",
            "VERIFIED",
            "The server verified at least one WebAuthn assertion, including the challenge, RP ID hash, origin, signature, and UV flag."
            + extra
            + " This is the demo relying party, not the customer's identity provider.",
        )
    if facts["webauthn_registrations"] >= 1:
        return _item("C", "Phishing-resistant MFA", "PARTIALLY VERIFIED", "A Passkey was registered, but no authentication assertion has been verified.")
    return _item("C", "Phishing-resistant MFA", "NOT VERIFIED", "No WebAuthn authentication with user verification has been verified.")


def _integrated(facts: dict) -> dict:
    if facts["integrated_sessions"] >= 1:
        return _item(
            "D",
            "Integrated authentication",
            "VERIFIED",
            "At least one server transaction recorded both factors and then issued a session. Separate API successes do not create that session.",
        )
    return _item("D", "Integrated authentication", "NOT VERIFIED", "No session has been issued from a transaction that passed both factors.")


def _sign_on_time(facts: dict) -> dict:
    if facts["timing_successes"] < 1:
        return _item("E", "Sign-on time <= 20 seconds", "NOT VERIFIED", "No corroborated successful sign-on measurement is stored.")
    if facts["over_target"] > 0:
        return _item(
            "E",
            "Sign-on time <= 20 seconds",
            "NOT VERIFIED",
            "At least one corroborated attempt exceeded 20 seconds. The average is not the acceptance criterion.",
        )
    if facts["timing_successes"] >= 10 and facts["timing_failures"] == 0 and facts["timer_discrepancies"] == 0:
        return _item(
            "E",
            "Sign-on time <= 20 seconds",
            "VERIFIED",
            "At least 10 corroborated successful journeys were recorded, every recorded attempt was within 20 seconds, and none disagreed with the server window by more than 15 seconds. This does not prove the customer's production sign-on time.",
        )
    return _item(
        "E",
        "Sign-on time <= 20 seconds",
        "PARTIALLY VERIFIED",
        "Recorded successes are within 20 seconds, but the sample has fewer than 10 successes, includes failures, or a device timer disagreed with the server window. The average alone is not treated as compliance.",
    )


def _performance(rows: list[dict]) -> dict:
    totals = [int(row["total_ms"]) for row in rows]
    successes = [row for row in rows if row["session_result"] == "PASS"]
    if not totals:
        return {
            "count": 0,
            "successes": 0,
            "failures": 0,
            "success_rate": "NOT TESTED",
            "minimum_ms": None,
            "maximum_ms": None,
            "average_ms": None,
            "p95_ms": None,
            "p95_note": "P95 is not calculated because there are no corroborated attempts.",
            "over_target": 0,
        }
    p95 = _percentile(totals, 95) if len(totals) >= 10 else None
    return {
        "count": len(totals),
        "successes": len(successes),
        "failures": len(totals) - len(successes),
        "success_rate": f"{(100.0 * len(successes) / len(totals)):.1f}%",
        "minimum_ms": min(totals),
        "maximum_ms": max(totals),
        "average_ms": round(sum(totals) / len(totals), 1),
        "p95_ms": p95,
        "p95_note": "P95 uses the nearest-rank method."
        if p95 is not None
        else "P95 is not calculated because the corroborated sample has fewer than 10 attempts.",
        "over_target": sum(1 for value in totals if value > TARGET_MS),
    }


def _percentile(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    rank = math.ceil(percentile / 100 * len(ordered))
    rank = min(max(rank, 1), len(ordered))
    return ordered[rank - 1]


def _device_view(row: dict) -> dict:
    return {
        "registration_id": row["registration_id"],
        "algorithm": row["algorithm"],
        "security_level": row["security_level"],
        "fingerprint": row["fingerprint"],
        "private_key_exportable": bool(row["private_key_exportable"]),
        "user_authentication_required": bool(row["user_authentication_required"]),
        "attestation_status": row["attestation_status"],
        "attestation_level": row["attestation_level"],
    }


def _credential_view(row: dict) -> dict:
    return {
        "username": row["username"],
        "device_type": row["device_type"],
        "backup_eligible": bool(row["backup_eligible"]),
        "backup_state": bool(row["backup_state"]),
        "user_verified": bool(row["user_verified"]),
        "sign_count": row["sign_count"],
    }


def _attempt_view(row: dict, number: int) -> dict:
    return {
        "attempt_number": number,
        "recorded_at": row["recorded_at"],
        "transaction_id": row["transaction_id"],
        "registration_id": row["registration_id"],
        "total_ms": row["total_ms"],
        "device_ms": row["device_ms"],
        "webauthn_ms": row["webauthn_ms"],
        "session_ms": row["session_ms"],
        "device_result": row["device_result"],
        "webauthn_result": row["webauthn_result"],
        "session_result": row["session_result"],
        "network_type": row["network_type"],
        "failure_reason": row["failure_reason"],
        "corroborated": bool(row["corroborated"]),
        "server_window_ms": row["server_window_ms"],
        "timer_discrepancy": bool(row["timer_discrepancy"]),
    }


def _latest_integrated(completed: list[dict], attempts: list[dict]) -> dict | None:
    if not completed:
        return None
    latest = completed[-1]
    match = next((row for row in reversed(attempts) if row["transaction_id"] == latest["transaction_id"]), None)
    return {
        "transaction_id": latest["transaction_id"],
        "device_result": latest["device_result"],
        "webauthn_result": latest["webauthn_result"],
        "session_result": "PASS" if latest["session_id"] else "FAIL",
        "total_ms": None if match is None else match["total_ms"],
    }


def _latest_negative_run() -> dict | None:
    rows = _rows("SELECT * FROM negative_runs ORDER BY id DESC LIMIT 1")
    if not rows:
        return None
    row = rows[0]
    return {
        "status": "RECORDED",
        "ran_at": row["ran_at"],
        "passed": bool(row["passed"]),
        "results": json.loads(row["results_json"]),
    }


def _latest_device_info(devices: list[dict], attempts: list[dict]) -> dict:
    for row in reversed(attempts):
        if row["device_info_json"]:
            try:
                parsed = json.loads(row["device_info_json"])
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict) and parsed.get("model"):
                return parsed
    for row in reversed(devices):
        if row["device_info_json"]:
            try:
                parsed = json.loads(row["device_info_json"])
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return {}


def _latest_network(attempts: list[dict]) -> str:
    for row in reversed(attempts):
        if row["network_type"]:
            return str(row["network_type"])
    return "NOT TESTED"


def _rows(sql: str) -> list[dict]:
    conn = connect()
    try:
        return [dict(row) for row in conn.execute(sql).fetchall()]
    finally:
        conn.close()


def _count(sql: str) -> int:
    conn = connect()
    try:
        return int(conn.execute(sql).fetchone()["n"])
    finally:
        conn.close()


def _limitations() -> list[str]:
    return [
        "This application is a reference implementation for technical verification.",
        "Successful testing shows that the demonstrated authentication architecture worked on the tested device under the tested conditions.",
        "It does not prove compatibility with the customer's identity provider, production application, or operational environment.",
        "It does not prove the customer's production sign-on time.",
        "A Passkey stored by Google Password Manager is not automatically device-bound.",
        "An Android Keystore key is not reported as hardware-backed unless attestation verifies against a pinned root.",
        "Empty sections were not executed. No result in this report was fabricated.",
    ]


def _item(item_id: str, title: str, status: str, rationale: str) -> dict:
    return {"id": item_id, "item": title, "status": status, "rationale": rationale}


def _safe(value: object) -> str:
    return str(value).encode("latin-1", errors="replace").decode("latin-1")


def _section(pdf: FPDF, title: str) -> None:
    pdf.ln(2)
    pdf.set_fill_color(11, 31, 51)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _safe(title), fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(20, 20, 20)
    pdf.ln(1)


def _body(pdf: FPDF, text: str) -> None:
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, _safe(text))
    pdf.ln(1)


class _Pdf(FPDF):
    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", size=8)
        self.set_text_color(80, 80, 80)
        self.cell(0, 8, f"Reference implementation | Page {self.page_no()}", align="C")
