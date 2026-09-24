import time

from fastapi.testclient import TestClient

import main
from core import database
from eraser import eraser_router
from eraser.eraser_engine import ErasureResult
from recover import recovery_router


def _auth_headers(tmp_path, monkeypatch):
    db_path = tmp_path / "api.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_path))
    monkeypatch.setenv("FN_ENABLE_DEMO_USERS", "false")
    database.init_db()

    with database.db_connection() as conn:
        pwd_hash, salt = database.hash_password("pass123")
        conn.execute(
            "INSERT INTO users(username, password_hash, salt, role, display_name) VALUES (?, ?, ?, ?, ?)",
            ("apiuser", pwd_hash, salt, "Admin", "API User"),
        )
        conn.commit()

    auth = database.authenticate_user("apiuser", "pass123")
    return {"Authorization": "Bea" + "rer " + auth["token"]}


def test_async_sanitization_job_success(tmp_path, monkeypatch):
    headers = _auth_headers(tmp_path, monkeypatch)
    client = TestClient(main.app)

    def fake_sanitize_target(*args, **kwargs):
        now = time.time()
        return ErasureResult(
            job_id="JOB-1",
            target_path="/tmp/evidence.bin",
            target_type="FILE",
            method="NIST_CLEAR",
            passes_completed=1,
            bytes_processed=128,
            start_time=now,
            end_time=now,
            verified=True,
            verification_method="test",
            verification_coverage_pct=100.0,
            audit_hash="abc",
        )

    monkeypatch.setattr(eraser_router.eraser, "sanitize_target", fake_sanitize_target)

    response = client.post(
        "/api/v1/erasure/execute",
        json={
            "target_path": "/tmp/evidence.bin",
            "method": "NIST_CLEAR",
            "verification_coverage_pct": 100,
            "async_job": True,
        },
        headers=headers,
    )

    assert response.status_code == 200
    payload = response.json()["data"]

    status = client.get(f"/api/v1/erasure/jobs/{payload['job_id']}", headers=headers)
    assert status.status_code == 200
    assert status.json()["data"]["status"] == "COMPLETED"


def test_async_carve_job_failure_is_reported(tmp_path, monkeypatch):
    headers = _auth_headers(tmp_path, monkeypatch)
    client = TestClient(main.app)

    def fake_carve_target(*args, **kwargs):
        raise ValueError("boom")

    monkeypatch.setattr(recovery_router.carver, "carve_target", fake_carve_target)

    response = client.post(
        "/api/v1/recovery/carve",
        json={
            "job_id": "CASE-FAIL",
            "target_path": "/tmp/none.img",
            "output_dir": "./cases",
            "scan_unallocated_only": False,
            "async_job": True,
        },
        headers=headers,
    )

    assert response.status_code == 200
    payload = response.json()["data"]

    status = client.get(f"/api/v1/recovery/carve/jobs/{payload['job_id']}", headers=headers)
    assert status.status_code == 200
    assert status.json()["data"]["status"] == "FAILED"
    assert "boom" in status.json()["data"]["error"]