"""
FIX LOG:
  - Original script just printed results without asserting anything, so a
    regression to the old "verified=True hardcoded" behavior would have looked
    identical to a real pass. Every test now asserts on the actual outcome.
  - Fixture files/folders are created if missing, so the script runs standalone
    instead of silently failing on a fresh checkout with no ./test_drive.raw.
  - Added a symlink-bypass test (proves the realpath-based protected-path fix)
    and an invalid-method test (proves the method validation fix).
"""

import json
import os
import secrets
from eraser_engine import SecureEraser


def _ensure_fixture_file(path: str, size_bytes: int = 65536):
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(b"CONFIDENTIAL-EVIDENCE-" + secrets.token_bytes(size_bytes))


def _ensure_fixture_folder(path: str):
    if not os.path.exists(path):
        os.makedirs(os.path.join(path, "sub"), exist_ok=True)
        with open(os.path.join(path, "note.txt"), "wb") as f:
            f.write(b"sensitive case notes\n" + secrets.token_bytes(4096))
        with open(os.path.join(path, "sub", "photo.bin"), "wb") as f:
            f.write(secrets.token_bytes(8192))


def run_tests():
    eraser = SecureEraser()

    print("=== TEST 1: Sanitize Synthetic Raw Disk Image (NIST_CLEAR) ===")
    _ensure_fixture_file("./test_drive.raw")
    res1 = eraser.sanitize(
        job_id="TEST-DISK-01",
        target_path="./test_drive.raw",
        method="NIST_CLEAR",
        is_active_evidence=False,
        verification_coverage=100.0
    )
    print(json.dumps(res1, indent=2))
    assert res1["verified"] is True, "Expected zero-fill read-back verification to pass"
    if os.path.exists("./test_drive.raw"):
        os.remove("./test_drive.raw")

    print("\n=== TEST 2: Active Evidence Safety Guardrail ===")
    _ensure_fixture_file("./test_drive2.raw")
    try:
        eraser.sanitize(
            job_id="TEST-SAFETY-01",
            target_path="./test_drive2.raw",
            method="NIST_CLEAR",
            is_active_evidence=True  # Should raise PermissionError
        )
        raise AssertionError("Expected PermissionError for an active-evidence target")
    except PermissionError as e:
        print(f"Safety Trigger Passed: {e}")
    finally:
        if os.path.exists("./test_drive2.raw"):
            os.remove("./test_drive2.raw")

    print("\n=== TEST 3: File / Folder Shredding (DoD 3-Pass) ===")
    _ensure_fixture_folder("./test_folder")
    res3 = eraser.sanitize(
        job_id="TEST-DIR-01",
        target_path="./test_folder",
        method="DOD_3PASS",
        is_active_evidence=False
    )
    print(json.dumps(res3, indent=2))
    assert res3["verified"] is True, "Expected DOD_3PASS folder erasure to verify"
    assert not os.path.exists("./test_folder"), "Folder should be gone after erasure"
    assert res3["bytes_processed"] > 0, "Folder byte accounting should reflect actual file contents"

    print("\n=== TEST 4: Protected-Path Symlink Bypass Guardrail ===")
    if os.path.islink("./sneaky_link"):
        os.remove("./sneaky_link")
    os.symlink("/etc", "./sneaky_link")
    try:
        eraser.sanitize(job_id="TEST-SAFETY-02", target_path="./sneaky_link", method="NIST_CLEAR")
        raise AssertionError("Expected PermissionError for a symlink pointing into a protected path")
    except PermissionError as e:
        print(f"Symlink Guardrail Passed: {e}")
    finally:
        if os.path.islink("./sneaky_link"):
            os.remove("./sneaky_link")

    print("\n=== TEST 5: Invalid Method Rejected ===")
    _ensure_fixture_file("./test_drive3.raw")
    try:
        eraser.sanitize(job_id="TEST-METHOD-01", target_path="./test_drive3.raw", method="NOT_A_REAL_METHOD")
        raise AssertionError("Expected ValueError for an unsupported method")
    except ValueError as e:
        print(f"Method Validation Passed: {e}")
    finally:
        if os.path.exists("./test_drive3.raw"):
            os.remove("./test_drive3.raw")

    print("\nAll tests completed.")


if __name__ == "__main__":
    run_tests()
