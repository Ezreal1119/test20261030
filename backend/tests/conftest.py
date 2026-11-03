import pytest


@pytest.fixture()
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setenv("RP_ID", "auth.example.com")
    monkeypatch.setenv("ORIGIN", "https://auth.example.com")
    monkeypatch.setenv("RP_NAME", "DT610 Verification")
    from app.db import init_db

    init_db()
    return tmp_path
