import sqlite3
import hashlib
import secrets
import time
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "forensic_nexus.db")

def hash_password(password: str, salt: str = None) -> tuple:
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return key.hex(), salt

def verify_password(stored_hash: str, salt: str, provided_password: str) -> bool:
    key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return secrets.compare_digest(key.hex(), stored_hash)

def init_db():
    conn = sqlite3.connect(DB_PATH)
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

    # Pre-seed fast testing credentials
    seed_users = [
        ("toib", "1234", "ErasureOperator", "Toib (Erasure Spec.)"),
        ("shaurya", "4321", "ForensicInvestigator", "Shaurya (Forensic Lead)"),
        ("ujjwal", "6969", "Admin", "Ujjwal (System Admin)")
    ]

    for u, p, r, d in seed_users:
        cur.execute("SELECT username FROM users WHERE username = ?", (u,))
        if not cur.fetchone():
            p_hash, salt = hash_password(p)
            cur.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?)", (u, p_hash, salt, r, d))

    conn.commit()
    conn.close()

def authenticate_user(username: str, password: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password_hash, salt, role, display_name FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    p_hash, salt, role, display_name = row
    if verify_password(p_hash, salt, password):
        token = secrets.token_hex(24)
        cur.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)", (token, username, role, time.time()))
        conn.commit()
        conn.close()
        return {"token": token, "username": username, "role": role, "display_name": display_name}
    conn.close()
    return None

def get_session(token: str):
    if not token:
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM sessions WHERE token = ?", (token,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def revoke_session(token: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()

def log_audit_event(job_data: dict):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO audit_vault (
                job_id, operation, target_path, target_type, method,
                bytes_processed, start_time, end_time, verified,
                verification_method, verification_coverage_pct,
                status, audit_hash, recovered_count, operator_username, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            job_data.get("job_id"), job_data.get("operation", "CARVE"),
            job_data.get("target_path", "/dev/sda1"), job_data.get("target_type", "BLOCK_DEVICE"),
            job_data.get("method", "N/A"), job_data.get("bytes_processed", 0),
            job_data.get("start_time", time.time()), job_data.get("end_time", time.time()),
            1 if job_data.get("verified", False) else 0, job_data.get("verification_method", "N/A"),
            job_data.get("verification_coverage_pct", 100.0), job_data.get("status", "COMPLETED"),
            job_data.get("audit_hash", "N/A"), job_data.get("recovered_count", 0),
            job_data.get("operator_username", "system"), time.time()
        ))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

def get_job(job_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_vault WHERE job_id = ?", (job_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["verified"] = bool(d["verified"])
        return d
    return None

def list_audit_ledger(role: str = "Admin") -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if role == "ErasureOperator":
        cur.execute("SELECT * FROM audit_vault WHERE operation = 'SANITIZATION' ORDER BY created_at DESC")
    else:
        cur.execute("SELECT * FROM audit_vault ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["verified"] = bool(d["verified"])
        results.append(d)
    return results

init_db()
