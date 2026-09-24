import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "forensic_nexus.db"
)
DB_TIMEOUT_SECONDS = float(os.getenv("FN_DB_TIMEOUT_SECONDS", "5"))
SESSION_TTL_SECONDS = int(os.getenv("FN_SESSION_TTL_SECONDS", "28800"))
APP_ENV = os.getenv("FN_ENV", "development").strip().lower()


@contextmanager
def db_connection(row_factory=None):
    conn = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT_SECONDS)

    if row_factory is not None:
        conn.row_factory = row_factory

    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")

    try:
        yield conn
    finally:
        conn.close()


def hash_password(
    password: str,
    salt: str | None = None,
) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
    )
    return key.hex(), salt


def verify_password(stored_hash: str, salt: str, provided_password: str) -> bool:
    key = hashlib.pbkdf2_hmac(
        "sha256", provided_password.encode("utf-8"), salt.encode("utf-8"), 100000
    )
    return secrets.compare_digest(key.hex(), stored_hash)


def _env_truthy(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _demo_seed_enabled() -> bool:
    default_enabled = APP_ENV in {"dev", "development", "local"}
    return _env_truthy(os.getenv("FN_ENABLE_DEMO_USERS"), default_enabled)


def _demo_seed_users() -> list[tuple[str, str, str, str]]:
    defaults = [
        (
            os.getenv("FN_DEMO_USER_ERASURE_USERNAME", "toib"),
            os.getenv("FN_DEMO_USER_ERASURE_PASSWORD", "1234"),
            "ErasureOperator",
            os.getenv("FN_DEMO_USER_ERASURE_DISPLAY", "Toib (Erasure Spec.)"),
        ),
        (
            os.getenv("FN_DEMO_USER_FORENSIC_USERNAME", "chethan"),
            os.getenv("FN_DEMO_USER_FORENSIC_PASSWORD", "4321"),
            "ForensicInvestigator",
            os.getenv("FN_DEMO_USER_FORENSIC_DISPLAY", "Chethan (Forensic Lead)"),
        ),
        (
            os.getenv("FN_DEMO_USER_ADMIN_USERNAME", "ujjwal"),
            os.getenv("FN_DEMO_USER_ADMIN_PASSWORD", "6969"),
            "Admin",
            os.getenv("FN_DEMO_USER_ADMIN_DISPLAY", "Ujjwal (System Admin)"),
        ),
    ]

    users: list[tuple[str, str, str, str]] = []
    for username, password, role, display_name in defaults:
        if not username or not password:
            continue
        users.append((username, password, role, display_name))

    return users


def init_db():
    with db_connection() as conn:
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                display_name TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_vault (
                job_id TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                target_path TEXT NOT NULL,
                target_type TEXT,
                method TEXT,
                bytes_processed INTEGER,
                start_time REAL,
                end_time REAL,
                verified INTEGER,
                verification_method TEXT,
                verification_coverage_pct REAL,
                status TEXT NOT NULL,
                audit_hash TEXT NOT NULL,
                recovered_count INTEGER DEFAULT 0,
                operator_username TEXT,
                created_at REAL NOT NULL
            )
        """)
        conn.commit()

        if _demo_seed_enabled():
            for u, p, r, d in _demo_seed_users():
                cur.execute("SELECT username FROM users WHERE username = ?", (u,))
                if cur.fetchone():
                    continue
                p_hash, salt = hash_password(p)
                cur.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?, ?)",
                    (u, p_hash, salt, r, d),
                )

            conn.commit()


def authenticate_user(username: str, password: str):
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT password_hash, salt, role, display_name FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        if not row:
            return None

        p_hash, salt, role, display_name = row
        if verify_password(p_hash, salt, password):
            token = secrets.token_hex(24)
            cur.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?)",
                (token, username, role, time.time()),
            )
            conn.commit()
            return {
                "token": token,
                "username": username,
                "role": role,
                "display_name": display_name,
            }

    return None


def get_session(token: str):
    if not token:
        return None

    now = time.time()

    with db_connection(row_factory=sqlite3.Row) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE token = ?", (token,))
        row = cur.fetchone()

        if not row:
            return None

        data = dict(row)
        ttl = max(1, SESSION_TTL_SECONDS)
        age_seconds = now - float(data.get("created_at", now))

        if age_seconds > ttl:
            cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            return None

        return data


def revoke_session(token: str):
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def log_audit_event(job_data: dict):
    with db_connection() as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO audit_vault (
                    job_id, operation, target_path, target_type, method,
                    bytes_processed, start_time, end_time, verified,
                    verification_method, verification_coverage_pct,
                    status, audit_hash, recovered_count, operator_username, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    job_data.get("job_id"),
                    job_data.get("operation", "CARVE"),
                    job_data.get("target_path", "/dev/sda1"),
                    job_data.get("target_type", "BLOCK_DEVICE"),
                    job_data.get("method", "N/A"),
                    job_data.get("bytes_processed", 0),
                    job_data.get("start_time", time.time()),
                    job_data.get("end_time", time.time()),
                    1 if job_data.get("verified", False) else 0,
                    job_data.get("verification_method", "N/A"),
                    job_data.get("verification_coverage_pct", 100.0),
                    job_data.get("status", "COMPLETED"),
                    job_data.get("audit_hash", "N/A"),
                    job_data.get("recovered_count", 0),
                    job_data.get("operator_username", "system"),
                    time.time(),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass


def get_job(job_id: str) -> dict:
    with db_connection(row_factory=sqlite3.Row) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM audit_vault WHERE job_id = ?", (job_id,))
        row = cur.fetchone()

    if row:
        d = dict(row)
        d["verified"] = bool(d["verified"])
        return d

    return None


def list_audit_ledger(role: str = "Admin") -> list:
    with db_connection(row_factory=sqlite3.Row) as conn:
        cur = conn.cursor()

        if role == "ErasureOperator":
            cur.execute(
                "SELECT * FROM audit_vault WHERE operation = 'SANITIZATION' ORDER BY created_at DESC"
            )
        else:
            cur.execute("SELECT * FROM audit_vault ORDER BY created_at DESC")

        rows = cur.fetchall()

    results = []
    for r in rows:
        d = dict(r)
        d["verified"] = bool(d["verified"])
        results.append(d)

    return results


init_db()
