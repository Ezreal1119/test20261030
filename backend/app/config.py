from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BACKEND_DIR / ".env"
BACKEND_VERSION = "1.0.0"


@dataclass(frozen=True)
class Settings:
    rp_id: str
    origin: str
    rp_name: str
    admin_token: str
    db_path: str
    data_dir: Path
    challenge_ttl_seconds: int
    transaction_ttl_seconds: int
    session_ttl_seconds: int
    package_name: str


def get_settings() -> Settings:
    load_dotenv(ENV_PATH, override=False)
    data_dir = Path(os.environ.get("DATA_DIR", BACKEND_DIR / "data")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    rp_id = os.environ.get("RP_ID", "example.com").strip()
    origin = os.environ.get("ORIGIN", "https://example.com").strip()
    if "://" in rp_id or "/" in rp_id:
        raise RuntimeError("RP_ID must be a bare hostname, without a scheme, port, or path")
    if not origin.startswith("https://"):
        raise RuntimeError("ORIGIN must be an https URL")
    token = os.environ.get("ADMIN_TOKEN", "").strip()
    token_file = data_dir / "admin_token"
    if not token and token_file.exists():
        token = token_file.read_text(encoding="utf-8").strip()
    db_path = os.environ.get("DB_PATH", str(data_dir / "verification.db"))
    return Settings(
        rp_id=rp_id,
        origin=origin.rstrip("/"),
        rp_name=os.environ.get("RP_NAME", "DT610 Auth Verification").strip(),
        admin_token=token,
        db_path=db_path,
        data_dir=data_dir,
        challenge_ttl_seconds=int(os.environ.get("CHALLENGE_TTL_SECONDS", "180")),
        transaction_ttl_seconds=int(os.environ.get("TRANSACTION_TTL_SECONDS", "300")),
        session_ttl_seconds=int(os.environ.get("SESSION_TTL_SECONDS", "900")),
        package_name=os.environ.get("ANDROID_PACKAGE", "com.patrick.test20261030").strip(),
    )


def ensure_admin_token() -> str:
    import secrets

    current = get_settings()
    if current.admin_token:
        return current.admin_token
    token = secrets.token_urlsafe(32)
    path = current.data_dir / "admin_token"
    path.write_text(token + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"Generated lab admin token: {token}", flush=True)
    return token


def rp_is_configured(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    return settings.rp_id not in {"example.com", "localhost"} and settings.origin == f"https://{settings.rp_id}"
