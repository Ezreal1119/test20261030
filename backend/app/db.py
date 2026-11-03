from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator

from app.config import get_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);
CREATE TABLE IF NOT EXISTS attestation_challenges (
    challenge_id TEXT PRIMARY KEY,
    challenge BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);
CREATE TABLE IF NOT EXISTS devices (
    registration_id TEXT PRIMARY KEY,
    public_key_spki BLOB NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL,
    security_level TEXT NOT NULL,
    user_authentication_required INTEGER NOT NULL,
    private_key_exportable INTEGER NOT NULL,
    key_alias TEXT NOT NULL,
    attestation_status TEXT NOT NULL,
    attestation_level TEXT,
    device_info_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_challenges (
    challenge_id TEXT PRIMARY KEY,
    registration_id TEXT NOT NULL,
    challenge BLOB NOT NULL,
    transaction_id TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);
CREATE TABLE IF NOT EXISTS device_verify_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_id TEXT,
    challenge_id TEXT,
    accepted INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webauthn_users (
    username TEXT PRIMARY KEY,
    user_id BLOB NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id_b64 TEXT PRIMARY KEY,
    credential_id BLOB NOT NULL,
    username TEXT NOT NULL,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL,
    aaguid TEXT,
    backup_eligible INTEGER NOT NULL,
    backup_state INTEGER NOT NULL,
    device_type TEXT NOT NULL,
    user_verified INTEGER NOT NULL,
    registration_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge_id TEXT PRIMARY KEY,
    challenge BLOB NOT NULL,
    purpose TEXT NOT NULL,
    username TEXT NOT NULL,
    transaction_id TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);
CREATE TABLE IF NOT EXISTS webauthn_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    credential_id_b64 TEXT,
    purpose TEXT NOT NULL,
    accepted INTEGER NOT NULL,
    user_verified INTEGER,
    backup_eligible INTEGER,
    backup_state INTEGER,
    device_type TEXT,
    origin TEXT,
    rp_id TEXT,
    reason TEXT NOT NULL,
    transaction_id TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_transactions (
    transaction_id TEXT PRIMARY KEY,
    registration_id TEXT NOT NULL,
    username TEXT NOT NULL,
    state TEXT NOT NULL,
    device_challenge_id TEXT,
    webauthn_challenge_id TEXT,
    device_result TEXT,
    webauthn_result TEXT,
    failure_reason TEXT,
    session_id TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    failed_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    transaction_id TEXT NOT NULL,
    registration_id TEXT NOT NULL,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at TEXT NOT NULL,
    transaction_id TEXT,
    registration_id TEXT,
    total_ms INTEGER NOT NULL,
    device_ms INTEGER NOT NULL,
    webauthn_ms INTEGER NOT NULL,
    session_ms INTEGER NOT NULL,
    device_result TEXT NOT NULL,
    webauthn_result TEXT NOT NULL,
    session_result TEXT NOT NULL,
    network_type TEXT,
    failure_reason TEXT,
    device_info_json TEXT,
    corroborated INTEGER NOT NULL,
    server_window_ms INTEGER,
    timer_discrepancy INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS negative_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ran_at TEXT NOT NULL,
    passed INTEGER NOT NULL,
    results_json TEXT NOT NULL
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def expires_in(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def millis_between(start: str, end: str) -> int:
    delta = datetime.fromisoformat(end) - datetime.fromisoformat(start)
    return int(delta.total_seconds() * 1000)


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(get_settings().db_path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


def get_setting(key: str, default: str = "") -> str:
    conn = connect()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return default if row is None else str(row["value"])
    finally:
        conn.close()


def set_setting(key: str, value: str) -> None:
    with transaction() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
