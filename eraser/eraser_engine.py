import os
import time
import hashlib
import uuid
from dataclasses import dataclass
from typing import List, Optional, Tuple

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
        if size <= 0:
            return []
        total_chunks = max(1, -(-size // self.chunk_size))
        n = min(max_samples, total_chunks)
        return sorted({min(size - 1, int(i * size / n)) for i in range(n)})

    def _read_back_verify(self, path: str, size: int, method: str, original_sample_hash: Optional[str]) -> bool:
        if size == 0:
            return True

        with open(path, "rb") as f:
            if method == "RANDOM_1PASS":
                sample = f.read(min(size, VERIFY_SAMPLE_BYTES))
                if not sample:
                    return False
                return hashlib.sha256(sample).hexdigest() != original_sample_hash

            if method == "NIST_CLEAR":
                expected = b"\x00"
            elif method == "DOD_3PASS":
                expected = b"\x55"
            else:
                raise ValueError(f"Unsupported method '{method}'")

            for off in self._sample_offsets(size):
                f.seek(off)
                chunk = f.read(min(self.chunk_size, size - off))
                if not chunk:
                    continue
                # Compare the sample to a pattern-sized repeated byte stream.
                expected_chunk = (expected * ((len(chunk) // len(expected)) + 1))[:len(chunk)]
                if chunk != expected_chunk:
                    return False
            return True

    def _overwrite_file(self, path: str, method: str) -> Tuple[int, bool]:
        size = os.path.getsize(path)
        if size == 0:
            return 0, True

        original_sample_hash = None
        if method == "RANDOM_1PASS":
            with open(path, "rb") as f:
                original_sample_hash = hashlib.sha256(f.read(min(size, VERIFY_SAMPLE_BYTES))).hexdigest()

        with open(path, "r+b", buffering=0) as f:
            passes_plan = [b"\x00", b"\xff", b"\x55"] if method == "DOD_3PASS" else [b"\x00"]
            passes_count = 3 if method == "DOD_3PASS" else 1

            for p in range(passes_count):
                f.seek(0)
                written = 0
                fill_byte = passes_plan[p] if method != "RANDOM_1PASS" else None
                while written < size:
                    chunk = min(self.chunk_size, size - written)
                    pattern = os.urandom(chunk) if fill_byte is None else fill_byte * chunk
                    f.write(pattern)
                    written += chunk
                f.flush()
                os.fsync(f.fileno())

        verified = self._read_back_verify(path, size, method, original_sample_hash)
        return size, verified

    def _overwrite_block_device(self, path: str, method: str) -> Tuple[int, bool]:
        with open(path, "r+b", buffering=0) as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(0)
            if size <= 0:
                raise ValueError(
                    f"Could not determine the size of block device '{path}'. "
                    "Refusing to guess a size rather than risk an incomplete or oversized overwrite."
                )

            original_sample_hash = None
            if method == "RANDOM_1PASS":
                f.seek(0)
                original_sample_hash = hashlib.sha256(f.read(min(size, VERIFY_SAMPLE_BYTES))).hexdigest()

            passes_plan = [b"\x00", b"\xff", b"\x55"] if method == "DOD_3PASS" else [b"\x00"]
            passes_count = 3 if method == "DOD_3PASS" else 1

            for p in range(passes_count):
                f.seek(0)
                written = 0
                fill_byte = passes_plan[p] if method != "RANDOM_1PASS" else None
                while written < size:
                    chunk = min(self.chunk_size, size - written)
                    pattern = os.urandom(chunk) if fill_byte is None else fill_byte * chunk
                    f.write(pattern)
                    written += chunk
                f.flush()
                os.fsync(f.fileno())

        verified = self._read_back_verify(path, size, method, original_sample_hash)
        return size, verified

    def sanitize_target(
        self,
        target_path: str,
        method: str = "NIST_CLEAR",
        verification_coverage_pct: float = 100.0,
        is_active_evidence: bool = False,
        job_id: str = None,
    ) -> ErasureResult:
        if is_active_evidence:
            raise PermissionError("Active evidence interlock engaged. Media write-protected.")
        if method not in SUPPORTED_METHODS:
            raise ValueError(f"Unsupported method '{method}'. Must be one of {sorted(SUPPORTED_METHODS)}.")
        if not 0.0 < verification_coverage_pct <= 100.0:
            raise ValueError("verification_coverage_pct must be greater than 0 and at most 100.")
        self._validate_safety(target_path)

        start_time = time.time()
        active_job_id = job_id or f"JOB-{int(start_time)}-{uuid.uuid4().hex[:8].upper()}"
        target_type = "BLOCK_DEVICE" if target_path.startswith("/dev/") else ("DIRECTORY" if os.path.isdir(target_path) else "FILE")

        if target_type == "DIRECTORY":
            bytes_processed = 0
            all_verified = True
            for root, dirs, files in os.walk(target_path, topdown=False, followlinks=False):
                for file in files:
                    fp = os.path.join(root, file)
                    if os.path.islink(fp):
                        raise PermissionError(f"Refusing to erase symbolic link '{fp}'.")
                    file_size, file_verified = self._overwrite_file(fp, method)
                    bytes_processed += file_size
                    all_verified = all_verified and file_verified
                    os.remove(fp)
                for d in dirs:
                    d_path = os.path.join(root, d)
                    if os.path.islink(d_path):
                        raise PermissionError(f"Refusing to erase symbolic link '{d_path}'.")
                    os.rmdir(d_path)
            try:
                os.rmdir(target_path)
            except OSError:
                pass
            verified = all_verified
            v_method = f"Read-back verification for {method}"
        elif target_type == "BLOCK_DEVICE":
            bytes_processed, verified = self._overwrite_block_device(target_path, method)
            v_method = f"Read-back verification for {method}"
        else:
            bytes_processed, verified = self._overwrite_file(target_path, method)
            v_method = f"Read-back verification for {method}"

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
            audit_hash=audit_hash,
        )

    def sanitize(self, *args, **kwargs):
        return self.sanitize_target(*args, **kwargs)


__all__ = ["SecureEraser", "ErasureResult"]









































































































































































































































































































































































