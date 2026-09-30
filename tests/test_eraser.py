import os
from pathlib import Path

import pytest

from eraser.eraser_engine import SecureEraser


def test_zero_fill_full_verification(tmp_path: Path):
    target = tmp_path / "evidence.bin"
    original = os.urandom(9000)
    target.write_bytes(original)

    result = SecureEraser(chunk_size=1024).sanitize_target(
        str(target),
        method="NIST_CLEAR",
        verification_coverage_pct=100,
    )

    assert result.verified is True
    assert result.verification_coverage_pct == 100.0
    assert target.read_bytes() == b"\x00" * len(original)


def test_random_verification(tmp_path: Path):
    target = tmp_path / "evidence.bin"
    original = os.urandom(10_000)
    target.write_bytes(original)

    result = SecureEraser(chunk_size=1000).sanitize_target(
        str(target),
        method="RANDOM_1PASS",
        verification_coverage_pct=20,
    )

    assert result.verified is True
    assert result.verification_coverage_pct == 100.0
    assert target.read_bytes() != original


def test_dod_three_pass(tmp_path: Path):
    target = tmp_path / "evidence.bin"
    target.write_bytes(os.urandom(5000))

    result = SecureEraser(chunk_size=512).sanitize_target(
        str(target),
        method="DOD_3PASS",
        verification_coverage_pct=100,
    )

    assert result.verified is True
    assert result.passes_completed == 3
    assert target.read_bytes() == b"\x55" * 5000


def test_invalid_method(tmp_path: Path):
    target = tmp_path / "evidence.bin"
    target.write_bytes(b"secret")

    with pytest.raises(ValueError):
        SecureEraser().sanitize_target(
            str(target),
            method="INVALID",
        )


def test_invalid_coverage(tmp_path: Path):
    target = tmp_path / "evidence.bin"
    target.write_bytes(b"secret")

    with pytest.raises(ValueError):
        SecureEraser().sanitize_target(
            str(target),
            verification_coverage_pct=0,
        )


def test_symlink_is_rejected(tmp_path: Path):
    target = tmp_path / "real.bin"
    link = tmp_path / "link.bin"

    target.write_bytes(b"secret")
    link.symlink_to(target)

    with pytest.raises(PermissionError):
        SecureEraser().sanitize_target(str(link))
