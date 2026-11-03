from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI, Header
from fastapi.responses import JSONResponse, Response

from app.config import BACKEND_VERSION, ensure_admin_token, get_settings, rp_is_configured
from app.db import init_db
from app.errors import ApiError
from app.services.attestation import load_pinned_roots
from app.services.device_auth import (
    create_attestation_challenge,
    create_device_challenge,
    create_enrollment_token,
    register_device,
    verify_device_challenge,
)
from app.services.encoding import compare_secret
from app.services.negative_tests import run_negative_tests, store_negative_run
from app.services.reporting import build_report, list_attempts, render_pdf
from app.services.transactions import (
    cancel_transaction,
    logout,
    read_session,
    record_attempt,
    start_transaction,
    submit_device,
    submit_webauthn,
)
from app.services.webauthn_service import (
    assetlinks_document,
    create_authentication_options,
    create_registration_options,
    credential_summary,
    fingerprints,
    finish_authentication,
    finish_registration,
    publish_assetlinks,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    ensure_admin_token()
    settings = get_settings()
    print(f"DT610 verification backend {BACKEND_VERSION}", flush=True)
    print(f"RP ID: {settings.rp_id}", flush=True)
    print(f"Origin: {settings.origin}", flush=True)
    print("Listening for lab API calls. Keep this process bound to localhost unless the tunnel is intentional.", flush=True)
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="DT610 Auth Verification", version=BACKEND_VERSION, lifespan=lifespan)

    @app.exception_handler(ApiError)
    async def handle_api_error(_request, exc: ApiError):
        return JSONResponse(status_code=exc.status, content={"ok": False, "error": str(exc)})

    @app.get("/")
    def root() -> dict:
        return {"service": "dt610-auth-verification", "version": BACKEND_VERSION}

    @app.get("/.well-known/assetlinks.json")
    def assetlinks() -> list:
        return assetlinks_document()

    api = APIRouter(prefix="/api", dependencies=[Depends(require_admin)])

    @api.get("/health")
    def health() -> dict:
        settings = get_settings()
        return {
            "ok": True,
            "version": BACKEND_VERSION,
            "rp_id": settings.rp_id,
            "origin": settings.origin,
            "rp_configured": rp_is_configured(settings),
            "fingerprints_configured": bool(fingerprints()),
            "attestation_roots": len(load_pinned_roots()),
        }

    @api.post("/admin/enrollment-tokens")
    def issue_token() -> dict:
        return create_enrollment_token()

    @api.put("/admin/assetlinks")
    def put_assetlinks(body: dict) -> dict:
        return publish_assetlinks(
            str(body.get("package_name", "")),
            list(body.get("sha256_cert_fingerprints") or []),
        )

    @api.post("/device/attestation-challenge")
    def attestation_challenge() -> dict:
        return create_attestation_challenge()

    @api.post("/device/register")
    def device_register(body: dict) -> dict:
        return register_device(body)

    @api.post("/device/challenge")
    def device_challenge(body: dict) -> dict:
        return create_device_challenge(str(body.get("registration_id", "")))

    @api.post("/device/verify")
    def device_verify(body: dict) -> dict:
        return verify_device_challenge(str(body.get("challenge_id", "")), str(body.get("signature", "")))

    @api.post("/webauthn/registration/options")
    def webauthn_registration_options(body: dict) -> dict:
        return create_registration_options(str(body.get("username", "")), body.get("registration_id"))

    @api.post("/webauthn/registration")
    def webauthn_registration(body: dict) -> dict:
        return finish_registration(
            str(body.get("challenge_id", "")),
            body.get("credential_json", {}),
            body.get("registration_id"),
        )

    @api.post("/webauthn/authentication/options")
    def webauthn_authentication_options(body: dict) -> dict:
        return create_authentication_options(str(body.get("username", "")))

    @api.post("/webauthn/authentication")
    def webauthn_authentication(body: dict) -> dict:
        return finish_authentication(str(body.get("challenge_id", "")), body.get("credential_json", {}))

    @api.get("/webauthn/credentials")
    def webauthn_credentials(username: str) -> dict:
        return credential_summary(username)

    @api.post("/auth/transactions")
    def auth_start(body: dict) -> dict:
        return start_transaction(str(body.get("registration_id", "")), str(body.get("username", "")))

    @api.post("/auth/transactions/{transaction_id}/device")
    def auth_device(transaction_id: str, body: dict) -> dict:
        return submit_device(transaction_id, str(body.get("signature", "")))

    @api.post("/auth/transactions/{transaction_id}/webauthn")
    def auth_webauthn(transaction_id: str, body: dict) -> dict:
        return submit_webauthn(transaction_id, body.get("credential_json", {}))

    @api.post("/auth/transactions/{transaction_id}/cancel")
    def auth_cancel(transaction_id: str, body: dict) -> dict:
        return cancel_transaction(transaction_id, str(body.get("reason", "")))

    @api.get("/auth/session")
    def auth_session(authorization: str = Header(default="")) -> dict:
        token = authorization.removeprefix("Bearer ").strip()
        if not token or token == authorization:
            raise ApiError("Session token is missing", 401)
        return read_session(token)

    @api.post("/auth/logout")
    def auth_logout(authorization: str = Header(default="")) -> dict:
        token = authorization.removeprefix("Bearer ").strip()
        return logout(token)

    @api.post("/auth/attempts")
    def auth_attempts(body: dict) -> dict:
        return record_attempt(body)

    @api.get("/auth/attempts")
    def auth_attempt_list(registration_id: str = "") -> dict:
        return list_attempts(registration_id or None)

    @api.post("/security/negative-tests")
    def security_tests() -> dict:
        payload = run_negative_tests()
        store_negative_run(payload)
        return payload

    @api.get("/reports/evidence.json")
    def evidence_json() -> dict:
        return build_report()

    @api.get("/reports/evidence.pdf")
    def evidence_pdf() -> Response:
        report = build_report()
        return Response(content=render_pdf(report), media_type="application/pdf")

    app.include_router(api)
    return app


def require_admin(x_admin_token: str = Header(default="")) -> None:
    if not compare_secret(x_admin_token, get_settings().admin_token):
        raise ApiError("Admin token was rejected", 401)


app = create_app()
