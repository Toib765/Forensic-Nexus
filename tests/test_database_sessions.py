import sqlite3
import time
from pathlib import Path

from core import database


def _configure_tmp_db(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_path))
    monkeypatch.setattr(database, "SESSION_TTL_SECONDS", 60)
    return db_path


def test_session_ttl_valid_and_expired(tmp_path: Path, monkeypatch):
    _configure_tmp_db(tmp_path, monkeypatch)
    monkeypatch.setenv("FN_ENABLE_DEMO_USERS", "false")
    database.init_db()

    now = time.time()
    with database.db_connection() as conn:
        conn.execute(
            "INSERT INTO sessions(token, username, role, created_at) VALUES (?, ?, ?, ?)",
            ("valid-token", "alice", "Admin", now),
        )
        conn.execute(
            "INSERT INTO sessions(token, username, role, created_at) VALUES (?, ?, ?, ?)",
            ("expired-token", "bob", "Admin", now - 3600),
        )
        conn.commit()

    valid = database.get_session("valid-token")
    assert valid is not None

    monkeypatch.setattr(database, "SESSION_TTL_SECONDS", 10)
    expired = database.get_session("expired-token")
    assert expired is None

    with database.db_connection() as conn:
        row = conn.execute(
            "SELECT token FROM sessions WHERE token = ?", ("expired-token",)
        ).fetchone()
        assert row is None


def test_revoked_session_is_removed(tmp_path: Path, monkeypatch):
    _configure_tmp_db(tmp_path, monkeypatch)
    monkeypatch.setenv("FN_ENABLE_DEMO_USERS", "false")
    database.init_db()

    with database.db_connection() as conn:
        conn.execute(
            "INSERT INTO sessions(token, username, role, created_at) VALUES (?, ?, ?, ?)",
            ("token-1", "alice", "Admin", time.time()),
        )
        conn.commit()

    database.revoke_session("token-1")
    assert database.get_session("token-1") is None


def test_demo_user_seeding_is_configurable(tmp_path: Path, monkeypatch):
    db_path = _configure_tmp_db(tmp_path, monkeypatch)

    monkeypatch.setenv("FN_ENABLE_DEMO_USERS", "false")
    database.init_db()

    with sqlite3.connect(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    assert count == 0

    monkeypatch.setenv("FN_ENABLE_DEMO_USERS", "true")
    monkeypatch.setenv("FN_DEMO_USER_ERASURE_USERNAME", "demo_erasure")
    monkeypatch.setenv("FN_DEMO_USER_ERASURE_PASSWORD", "safe-pass")
    database.init_db()

    auth = database.authenticate_user("demo_erasure", "safe-pass")
    assert auth is not None
    assert auth["role"] == "ErasureOperator"
