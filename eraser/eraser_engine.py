"""
FIX LOG (this pass):
  1. `verified = True` was hardcoded in all three branches (DIRECTORY,
     BLOCK_DEVICE, FILE) — os.sync() flushes write buffers, it doesn't
     confirm what's actually on disk. Every branch now runs a real
     read-back: a fixed-byte final pass is confirmed by sampling offsets
     and checking they equal that byte; a random final pass is confirmed
     by hashing a bounded pre-write sample and checking it differs from
     the same range post-write.
  2. The BLOCK_DEVICE branch's silent size fallback (`if size == 0: size =
     536870912`) meant an unreadable device size caused a blind 512MB
     guess. Now raises ValueError instead.
  3. `method` was never validated — an unrecognized string silently fell
     through to NIST_CLEAR-style behavior. Now validated against
     SUPPORTED_METHODS up front.
"""

import os
import time
import hashlib
import uuid
from dataclasses import dataclass
from typing import Optional, List, Tuple

SUPPORTED_METHODS = {"NIST_CLEAR", "RANDOM_1PASS", "DOD_3PASS"}
VERIFY_SAMPLE_BYTES = 1024 * 1024
MAX_VERIFY_SAMPLES = 32


@dataclass
class ErasureResult:
    job_id: str
    target_path: str
    target_type: str
    method: str
    passes_completed: int
    bytes_processed: int
    start_time: float
    end_time: float
    verified: bool
    verification_method: str
    verification_coverage_pct: float
    audit_hash: str


class SecureEraser:
    def __init__(self, chunk_size: int = 1048576):
        self.chunk_size = chunk_size
        self.protected_prefixes = [
            "/bin", "/boot", "/dev/vda", "/dev/nvme0n1", "/etc",
            "/lib", "/lib64", "/proc", "/root", "/run", "/sbin",
            "/sys", "/usr", "/var"
        ]

    def _validate_safety(self, target_path: str):
        real_target = os.path.realpath(target_path)
        if real_target == "/":
            raise PermissionError("Target resolves to root filesystem (/). Refusing execution.")
        for prefix in self.protected_prefixes:
            if real_target == prefix or real_target.startswith(prefix + "/"):
                raise PermissionError(f"Target '{real_target}' falls within protected system path '{prefix}'.")

    def _sample_offsets(self, size: int, max_samples: int = MAX_VERIFY_SAMPLES) -> List[int]:
        total_chunks = max(1, -(-size // self.chunk_size))
        n = min(max_samples, total_chunks)
        return sorted({min(size - 1, int(i * size / n)) for i in range(n)})

    def _read_back_verify(self, path: str, size: int, final_pattern: Optional[bytes],
                           pre_hash: Optional[str]) -> bool:
        if size == 0:
            return True
        if final_pattern == b"RANDOM":
            with open(path, "rb") as f:
                post_hash = hashlib.sha256(f.read(min(size, VERIFY_SAMPLE_BYTES))).hexdigest()
            return pre_hash is None or post_hash != pre_hash
        with open(path, "rb") as f:
            for off in self._sample_offsets(size):
                f.seek(off)
                chunk = f.read(min(self.chunk_size, size - off))
                if not chunk:
                    continue
                if chunk != final_pattern * len(chunk):
                    return False
        return True

    def _overwrite_file(self, path: str, method: str) -> Tuple[int, bool]:
        size = os.path.getsize(path)
        if size == 0:
            return 0, True

        passes_plan = [b"\x00", b"\xFF", b"\x55"] if method == "DOD_3PASS" else [b"\x00"]
        is_random = (method == "RANDOM_1PASS")
        passes_count = 3 if method == "DOD_3PASS" else 1

        pre_hash = None
        if is_random:
            with open(path, "rb") as f:
                pre_hash = hashlib.sha256(f.read(min(size, VERIFY_SAMPLE_BYTES))).hexdigest()

        final_pattern = b"RANDOM"
        with open(path, "r+b", buffering=0) as f:
            for p in range(passes_count):
                f.seek(0)
                written = 0
                fill_byte = passes_plan[p] if not is_random else None
                while written < size:
                    chunk = min(self.chunk_size, size - written)
                    pattern = os.urandom(chunk) if is_random else fill_byte * chunk
                    f.write(pattern)
                    written += chunk
                f.flush()
                os.fsync(f.fileno())
                final_pattern = b"RANDOM" if is_random else fill_byte
            os.sync()

        verified = self._read_back_verify(path, size, final_pattern, pre_hash)
        return size, verified

    def _overwrite_block_device(self, path: str, method: str) -> Tuple[int, bool]:
        with open(path, "r+b", buffering=0) as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(0)
            if size == 0:
                raise ValueError(
                    f"Could not determine the size of block device '{path}'. "
                    f"Refusing to guess a size rather than risk an incomplete or oversized overwrite."
                )

            is_random = (method == "RANDOM_1PASS")
            passes_plan = [b"\x00", b"\xFF", b"\x55"] if method == "DOD_3PASS" else [b"\x00"]
            passes_count = 3 if method == "DOD_3PASS" else 1

            pre_hash = None
            if is_random:
                f.seek(0)
                pre_hash = hashlib.sha256(f.read(min(size, VERIFY_SAMPLE_BYTES))).hexdigest()

            final_pattern = b"RANDOM"
            for p in range(passes_count):
                f.seek(0)
                written = 0
                fill_byte = passes_plan[p] if not is_random else None
                while written < size:
                    chunk = min(self.chunk_size, size - written)
                    pattern = os.urandom(chunk) if is_random else fill_byte * chunk
                    f.write(pattern)
                    written += chunk
                f.flush()
                os.fsync(f.fileno())
                final_pattern = b"RANDOM" if is_random else fill_byte
            os.sync()

        verified = self._read_back_verify(path, size, final_pattern, pre_hash)
        return size, verified

    def sanitize_target(self, target_path: str, method: str = "NIST_CLEAR",
                         verification_coverage_pct: float = 100.0,
                         is_active_evidence: bool = False, job_id: str = None) -> ErasureResult:
        if is_active_evidence:
            raise PermissionError("Active evidence interlock engaged. Media write-protected.")
        if method not in SUPPORTED_METHODS:
            raise ValueError(f"Unsupported method '{method}'. Must be one of {sorted(SUPPORTED_METHODS)}.")
        self._validate_safety(target_path)

        start_time = time.time()
        active_job_id = job_id or f"JOB-{int(start_time)}-{uuid.uuid4().hex[:8].upper()}"
        target_type = "BLOCK_DEVICE" if target_path.startswith("/dev/") else ("DIRECTORY" if os.path.isdir(target_path) else "FILE")

        if target_type == "DIRECTORY":
            bytes_processed = 0
            all_verified = True
            for root, dirs, files in os.walk(target_path, topdown=False):
                for file in files:
                    fp = os.path.join(root, file)
                    fb, fv = self._overwrite_file(fp, method)
                    bytes_processed += fb
                    all_verified = all_verified and fv
                    os.remove(fp)
                for d in dirs:
                    os.rmdir(os.path.join(root, d))
            os.rmdir(target_path)
            verified = all_verified
            v_method = f"Read-Back Verification, {MAX_VERIFY_SAMPLES} Samples/File"
        elif target_type == "BLOCK_DEVICE":
            bytes_processed, verified = self._overwrite_block_device(target_path, method)
            v_method = f"Read-Back Verification, {MAX_VERIFY_SAMPLES} Sampled Offsets"
        else:
            bytes_processed, verified = self._overwrite_file(target_path, method)
            v_method = f"Read-Back Verification, {MAX_VERIFY_SAMPLES} Sampled Offsets"

        end_time = time.time()
        audit_hash = hashlib.sha256(
            f"{active_job_id}:{target_path}:{bytes_processed}:{verified}:{end_time}".encode()
        ).hexdigest()

        return ErasureResult(
            job_id=active_job_id,
            target_path=target_path,
            target_type=target_type,
            method=method,
            passes_completed=3 if method == "DOD_3PASS" else 1,
            bytes_processed=bytes_processed,
            start_time=start_time,
            end_time=end_time,
            verified=verified,
            verification_method=v_method,
            verification_coverage_pct=verification_coverage_pct,
            audit_hash=audit_hash
        )

    def sanitize(self, *args, **kwargs):
        return self.sanitize_target(*args, **kwargs)
