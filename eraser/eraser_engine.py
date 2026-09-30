import errno
import fcntl
import hashlib
import os
import struct
import time
import uuid
from dataclasses import dataclass

SUPPORTED_METHODS = {"NIST_CLEAR", "RANDOM_1PASS", "DOD_3PASS"}
BLKGETSIZE64 = 0x80081272


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
    processed_files: int = 0
    verified_files: int = 0
    failed_files: int = 0
    failures: list[dict] | None = None


class SecureEraser:
    def __init__(self, chunk_size: int = 1024 * 1024):
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

        self.chunk_size = chunk_size
        self.protected_prefixes = {
            "/bin",
            "/boot",
            "/etc",
            "/lib",
            "/lib64",
            "/proc",
            "/root",
            "/run",
            "/sbin",
            "/sys",
            "/usr",
            "/var",
        }

    def _validate_request(
        self,
        target_path: str,
        method: str,
        coverage: float,
    ) -> None:
        if method not in SUPPORTED_METHODS:
            raise ValueError(
                f"Unsupported method '{method}'. "
                f"Use one of {sorted(SUPPORTED_METHODS)}."
            )

        if not 0 < coverage <= 100:
            raise ValueError(
                "verification_coverage_pct must be greater than 0 and at most 100."
            )

        if not target_path or not os.path.lexists(target_path):
            raise FileNotFoundError(f"Target '{target_path}' does not exist.")

        if os.path.islink(target_path):
            raise PermissionError("Refusing to erase a symbolic link.")

    def _validate_safety(self, target_path: str) -> None:
        real_target = os.path.realpath(target_path)

        if real_target == "/":
            raise PermissionError(
                "Target resolves to the root filesystem. Refusing execution."
            )

        # Device safety is checked by DriveScanner and the router.
        if real_target.startswith("/dev/"):
            return

        for prefix in self.protected_prefixes:
            if real_target == prefix or real_target.startswith(prefix + "/"):
                raise PermissionError(
                    f"Target '{real_target}' is inside protected path '{prefix}'."
                )

    def _get_block_device_size(self, fd: int, path: str) -> int:
        try:
            result = fcntl.ioctl(fd, BLKGETSIZE64, b"\x00" * 8)
            size = struct.unpack("Q", result)[0]
        except (OSError, struct.error) as exc:
            raise PermissionError(
                f"Cannot determine the exact size of '{path}'. Refusing to guess."
            ) from exc

        if size <= 0:
            raise ValueError(f"Invalid size reported for block device '{path}'.")

        return size

    def _verification_indices(
        self,
        total_chunks: int,
        coverage_pct: float,
    ) -> list[int]:
        if total_chunks <= 0:
            return []

        if coverage_pct >= 100:
            return list(range(total_chunks))

        count = max(1, round(total_chunks * coverage_pct / 100))
        step = total_chunks / count

        return sorted(
            {min(total_chunks - 1, int(index * step)) for index in range(count)}
        )

    def _pattern(
        self,
        method: str,
        pass_index: int,
        length: int,
    ) -> bytes | None:
        if method == "RANDOM_1PASS":
            return None

        if method == "DOD_3PASS":
            return (b"\x00", b"\xff", b"\x55")[pass_index] * length

        return b"\x00" * length

    def _overwrite_and_verify(
        self,
        path: str,
        size: int,
        method: str,
        coverage_pct: float,
    ) -> tuple[int, bool, float, int]:
        if size == 0:
            return 0, True, 100.0, 0

        total_chunks = (size + self.chunk_size - 1) // self.chunk_size
        verify_indices = self._verification_indices(
            total_chunks,
            coverage_pct,
        )

        verify_set = set(verify_indices)
        random_hashes: dict[int, bytes] = {}
        pass_count = 3 if method == "DOD_3PASS" else 1

        original_hash = None

        with open(path, "r+b", buffering=0) as stream:
            if method == "RANDOM_1PASS":
                stream.seek(0)
                original = stream.read(min(size, self.chunk_size))
                original_hash = hashlib.sha256(original).digest()

            for pass_index in range(pass_count):
                stream.seek(0)

                for chunk_index in range(total_chunks):
                    offset = chunk_index * self.chunk_size
                    length = min(self.chunk_size, size - offset)

                    data = self._pattern(method, pass_index, length)

                    if data is None:
                        data = os.urandom(length)

                        if chunk_index in verify_set:
                            random_hashes[chunk_index] = hashlib.sha256(data).digest()

                    written = stream.write(data)

                    if written != length:
                        raise OSError(
                            errno.EIO,
                            f"Short write while erasing '{path}'.",
                        )

                stream.flush()
                os.fsync(stream.fileno())

        verified_count = 0

        with open(path, "rb", buffering=0) as stream:
            for chunk_index in verify_indices:
                offset = chunk_index * self.chunk_size
                length = min(self.chunk_size, size - offset)

                stream.seek(offset)
                actual = stream.read(length)

                if len(actual) != length:
                    return (
                        size,
                        False,
                        self._coverage(verified_count, len(verify_indices)),
                        pass_count,
                    )

                if method == "RANDOM_1PASS":
                    valid = hashlib.sha256(actual).digest() == random_hashes.get(
                        chunk_index
                    )
                else:
                    expected = self._pattern(
                        method,
                        pass_count - 1,
                        length,
                    )
                    valid = actual == expected

                if not valid:
                    return (
                        size,
                        False,
                        self._coverage(verified_count, len(verify_indices)),
                        pass_count,
                    )

                verified_count += 1

        if method == "RANDOM_1PASS" and original_hash is not None:
            with open(path, "rb") as stream:
                current = hashlib.sha256(
                    stream.read(min(size, self.chunk_size))
                ).digest()

            if current == original_hash:
                return size, False, 0.0, pass_count

        return (
            size,
            True,
            self._coverage(verified_count, len(verify_indices)),
            pass_count,
        )

    @staticmethod
    def _coverage(verified: int, total: int) -> float:
        if total == 0:
            return 100.0
        return round((verified / total) * 100, 2)

    def sanitize_target(
        self,
        target_path: str,
        method: str = "NIST_CLEAR",
        verification_coverage_pct: float = 100.0,
        is_active_evidence: bool = False,
        job_id: str | None = None,
    ) -> ErasureResult:
        if is_active_evidence:
            raise PermissionError(
                "Active evidence interlock engaged. Media write-protected."
            )

        self._validate_request(
            target_path,
            method,
            verification_coverage_pct,
        )
        self._validate_safety(target_path)

        start_time = time.time()
        active_job_id = job_id or (
            f"JOB-{int(start_time)}-{uuid.uuid4().hex[:8].upper()}"
        )

        target_type = (
            "BLOCK_DEVICE"
            if os.path.abspath(target_path).startswith("/dev/")
            else "DIRECTORY"
            if os.path.isdir(target_path)
            else "FILE"
        )

        bytes_processed = 0
        verified = True
        coverages: list[float] = []
        passes_completed = 0
        processed_files = 0
        verified_files = 0
        failed_files = 0
        failures: list[dict] = []

        if target_type == "DIRECTORY":
            for root, dirs, files in os.walk(
                target_path,
                topdown=False,
                followlinks=False,
            ):
                for name in files:
                    file_path = os.path.join(root, name)

                    if os.path.islink(file_path):
                        failures.append(
                            {
                                "path": file_path,
                                "reason": "Symbolic link refused",
                            }
                        )
                        failed_files += 1
                        verified = False
                        continue

                    try:
                        size = os.path.getsize(file_path)
                        result = self._overwrite_and_verify(
                            file_path,
                            size,
                            method,
                            verification_coverage_pct,
                        )

                        processed, file_ok, actual, passes = result
                        bytes_processed += processed
                        coverages.append(actual)
                        passes_completed = max(
                            passes_completed,
                            passes,
                        )
                        processed_files += 1

                        if not file_ok:
                            verified = False
                            failed_files += 1
                            failures.append(
                                {
                                    "path": file_path,
                                    "reason": "Read-back verification failed",
                                }
                            )
                            # Never delete after failed verification.
                            continue

                        verified_files += 1
                        os.remove(file_path)

                    except Exception as exc:
                        verified = False
                        failed_files += 1
                        failures.append(
                            {
                                "path": file_path,
                                "reason": str(exc),
                            }
                        )

                for name in dirs:
                    directory = os.path.join(root, name)

                    if os.path.islink(directory):
                        verified = False
                        failures.append(
                            {
                                "path": directory,
                                "reason": "Symbolic link refused",
                            }
                        )
                        continue

                    try:
                        os.rmdir(directory)
                    except OSError:
                        verified = False

            if verified:
                try:
                    os.rmdir(target_path)
                except OSError as exc:
                    verified = False
                    failures.append(
                        {
                            "path": target_path,
                            "reason": str(exc),
                        }
                    )

            verification_method = "Exact read-back verification of selected file chunks"

        elif target_type == "BLOCK_DEVICE":
            with open(target_path, "rb", buffering=0) as stream:
                size = self._get_block_device_size(
                    stream.fileno(),
                    target_path,
                )

            (
                bytes_processed,
                verified,
                actual,
                passes_completed,
            ) = self._overwrite_and_verify(
                target_path,
                size,
                method,
                verification_coverage_pct,
            )

            coverages.append(actual)
            verification_method = (
                "Exact read-back verification of selected device chunks"
            )

        else:
            size = os.path.getsize(target_path)

            (
                bytes_processed,
                verified,
                actual,
                passes_completed,
            ) = self._overwrite_and_verify(
                target_path,
                size,
                method,
                verification_coverage_pct,
            )

            coverages.append(actual)
            verification_method = "Exact read-back verification of selected file chunks"

        end_time = time.time()
        actual_coverage = (
            round(sum(coverages) / len(coverages), 2) if coverages else 100.0
        )

        if not verified:
            status = "PARTIAL_FAILURE" if processed_files else "VERIFICATION_FAILED"
        else:
            status = "SANITIZED"

        audit_hash = hashlib.sha256(
            (
                f"{active_job_id}:{target_path}:{bytes_processed}:"
                f"{verified}:{actual_coverage}:{status}:{end_time}"
            ).encode()
        ).hexdigest()

        return ErasureResult(
            job_id=active_job_id,
            target_path=target_path,
            target_type=target_type,
            method=method,
            passes_completed=passes_completed,
            bytes_processed=bytes_processed,
            start_time=start_time,
            end_time=end_time,
            verified=verified,
            verification_method=verification_method,
            verification_coverage_pct=actual_coverage,
            audit_hash=audit_hash,
            processed_files=processed_files,
            verified_files=verified_files,
            failed_files=failed_files,
            failures=failures,
        )

    def sanitize(self, *args, **kwargs):
        return self.sanitize_target(*args, **kwargs)


__all__ = ["ErasureResult", "SecureEraser"]
