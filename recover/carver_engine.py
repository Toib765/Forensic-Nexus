import fcntl
import hashlib
import math
import os
import struct
import time
import uuid
from typing import Any

from recover.atom_carver import AtomCarver
from recover.fat_extractor import FatExtractor


class StreamCarver:
    def __init__(
        self,
        block_size: int = 65536,
        scan_chunk_size: int = 4 * 1024 * 1024,
    ):
        self.block_size = block_size
        self.scan_chunk_size = scan_chunk_size
        self.max_carve_size = 25 * 1024 * 1024
        self._signature_headers = [
            b"\x89PNG\r\n\x1a\n",
            b"\xff\xd8\xff",
            b"%PDF-",
            b"PK\x03\x04",
            b"SQLite format 3\x00",
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
        ]
        self._ftyp = b"ftyp"
        self._search_overlap = max(len(hdr) for hdr in self._signature_headers) + 8

    def _get_target_size(self, fd: int, target_path: str) -> int:
        if target_path.startswith("/dev/"):
            try:
                result = fcntl.ioctl(
                    fd,
                    0x80081272,
                    b"\x00" * 8,
                )
                size = struct.unpack("Q", result)[0]

                if size <= 0:
                    raise ValueError(
                        f"Invalid block-device size for '{target_path}'."
                    )

                return size

            except (OSError, struct.error, ValueError) as exc:
                raise PermissionError(
                    f"Unable to determine the exact size of '{target_path}'. "
                    "Refusing to scan an unknown device size."
                ) from exc

        return os.path.getsize(target_path)

    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count == 0:
                continue
            p = count / len(data)
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def classify_entropy(self, entropy: float, data: bytes) -> str:
        if entropy == 0.0 or data == b"\x00" * len(data):
            return "ZEROED_SANITIZED"
        if entropy < 4.5:
            return "STRUCTURED_UNCOMPRESSED"
        return "COMPRESSED_OR_ENCRYPTED"

    def _normalized_ranges(
        self,
        raw_ranges: list[tuple[int, int]],
        target_bytes: int,
    ) -> list[tuple[int, int]]:
        normalized: list[tuple[int, int]] = []

        for start, end in sorted(raw_ranges, key=lambda item: item[0]):
            s = max(0, int(start))
            e = min(target_bytes, int(end))

            if e <= s:
                continue

            if normalized and s <= normalized[-1][1]:
                normalized[-1] = (normalized[-1][0], max(normalized[-1][1], e))
            else:
                normalized.append((s, e))

        return normalized

    def _resolve_scan_ranges(
        self,
        target_path: str,
        target_bytes: int,
        scan_unallocated_only: bool,
    ) -> tuple[str, list[tuple[int, int]], list[dict[str, int]]]:
        if not scan_unallocated_only:
            ranges = [(0, target_bytes)]
            return (
                "FULL_RAW_STREAM",
                ranges,
                [{"start_byte": 0, "end_byte": target_bytes}],
            )

        extractor = FatExtractor(target_path)
        if not extractor.parse_boot_sector():
            raise ValueError(
                "Unallocated-only carving is currently supported only for FAT/FAT32 "
                "targets with a valid boot sector."
            )

        _, raw_ranges = extractor.get_cluster_allocation_map()
        ranges = self._normalized_ranges(raw_ranges, target_bytes)

        if not ranges:
            raise ValueError(
                "No unallocated FAT/FAT32 ranges were detected for this target."
            )

        range_manifest = [
            {"start_byte": start, "end_byte": end} for start, end in ranges
        ]

        return "UNALLOCATED_ONLY", ranges, range_manifest

    def _iter_entropy_blocks(self, stream, scan_ranges: list[tuple[int, int]]):
        for start, end in scan_ranges:
            offset = start
            while offset < end:
                size = min(self.block_size, end - offset)
                stream.seek(offset)
                chunk = stream.read(size)
                if not chunk:
                    break
                yield offset, chunk
                offset += len(chunk)

    def _find_candidates_in_buffer(self, data: bytes) -> list[int]:
        positions: set[int] = set()

        for header in self._signature_headers:
            cursor = 0
            while True:
                pos = data.find(header, cursor)
                if pos < 0:
                    break
                positions.add(pos)
                cursor = pos + 1

        cursor = 0
        while True:
            pos = data.find(self._ftyp, cursor)
            if pos < 0:
                break
            if pos >= 4:
                positions.add(pos - 4)
            cursor = pos + 1

        return sorted(positions)

    def _iter_candidate_offsets(self, stream, scan_ranges: list[tuple[int, int]]):
        seen: set[int] = set()

        for range_start, range_end in scan_ranges:
            offset = range_start
            carry = b""

            while offset < range_end:
                size = min(self.scan_chunk_size, range_end - offset)
                stream.seek(offset)
                chunk = stream.read(size)
                if not chunk:
                    break

                base_offset = offset - len(carry)
                merged = carry + chunk

                for local_pos in self._find_candidates_in_buffer(merged):
                    absolute = base_offset + local_pos
                    if absolute < range_start or absolute >= range_end:
                        continue
                    if absolute in seen:
                        continue
                    seen.add(absolute)
                    yield absolute

                carry = merged[-self._search_overlap :]
                offset += len(chunk)

    @staticmethod
    def _range_for_offset(
        offset: int,
        scan_ranges: list[tuple[int, int]],
    ) -> tuple[int, int] | None:
        for start, end in scan_ranges:
            if start <= offset < end:
                return start, end
        return None

    def _read_window(
        self,
        stream,
        offset: int,
        target_bytes: int,
        range_end: int,
    ) -> bytes:
        available = min(self.max_carve_size, target_bytes - offset, range_end - offset)
        if available <= 0:
            return b""
        stream.seek(offset)
        return stream.read(available)

    def _carve_at_offset(
        self,
        stream,
        target_path: str,
        offset: int,
        target_bytes: int,
        range_end: int,
    ) -> tuple[str, str, str, int, bytes] | None:
        artifact = self._read_window(stream, offset, target_bytes, range_end)
        if len(artifact) < 8:
            return None

        file_type = ""
        extension = ""
        category = ""
        confidence = 0
        size = 0

        if artifact.startswith(b"\x89PNG\r\n\x1a\n"):
            iend = artifact.find(b"IEND")
            if iend != -1 and iend + 8 <= len(artifact):
                size = iend + 8
                file_type, extension, category, confidence = (
                    "PNG Image",
                    "png",
                    "Images",
                    100,
                )

        elif artifact.startswith(b"\xff\xd8\xff"):
            eoi = artifact.find(b"\xff\xd9", 2)
            if eoi != -1 and eoi + 2 <= len(artifact):
                size = eoi + 2
                file_type, extension, category, confidence = (
                    "JPEG Image",
                    "jpg",
                    "Images",
                    100,
                )

        elif artifact.startswith(b"%PDF-"):
            eof_idx = artifact.find(b"%%EOF")
            if eof_idx != -1:
                size = eof_idx + 5
                file_type, extension, category, confidence = (
                    "PDF Document",
                    "pdf",
                    "Documents",
                    100,
                )

        elif artifact.startswith(b"PK\x03\x04"):
            eocd = artifact.find(b"PK\x05\x06")
            if eocd != -1 and eocd + 22 <= len(artifact):
                comment_len = struct.unpack("<H", artifact[eocd + 20 : eocd + 22])[0]
                calculated = eocd + 22 + comment_len
                if calculated <= len(artifact):
                    size = calculated
                    sample_slice = artifact[: min(4096, len(artifact))]
                    category = "Documents"
                    if b"word/" in sample_slice:
                        file_type, extension = "DOCX Document", "docx"
                    elif b"ppt/" in sample_slice:
                        file_type, extension = "PPTX Presentation", "pptx"
                    elif b"xl/" in sample_slice:
                        file_type, extension = "XLSX Spreadsheet", "xlsx"
                    else:
                        file_type, extension = "ZIP Archive", "zip"
                    confidence = 100

        elif artifact.startswith(b"SQLite format 3\x00") and len(artifact) >= 100:
            page_size_raw = struct.unpack(">H", artifact[16:18])[0]
            page_size = 65536 if page_size_raw == 1 else page_size_raw
            page_count = struct.unpack(">I", artifact[28:32])[0]

            if page_size > 0 and page_count > 0:
                calculated = page_size * page_count
                max_available = min(len(artifact), target_bytes - offset, range_end - offset)

                if 512 <= calculated <= self.max_carve_size:
                    if calculated <= max_available:
                        size = calculated
                        file_type, extension, category, confidence = (
                            "SQLite Database",
                            "db",
                            "Databases",
                            100,
                        )
                    elif max_available >= 512:
                        size = max_available
                        file_type, extension, category, confidence = (
                            "SQLite Database (Truncated)",
                            "db",
                            "Databases",
                            40,
                        )

        elif artifact[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            size = min(4096, len(artifact))
            file_type, extension, category, confidence = (
                "PCAP Network Capture",
                "pcap",
                "Network",
                90,
            )

        elif len(artifact) >= 8 and artifact[4:8] == b"ftyp":
            max_size = min(self.max_carve_size, range_end - offset)
            with open(target_path, "rb") as mp4_stream:
                ok, atom_len = AtomCarver.parse_mp4_stream(
                    mp4_stream,
                    offset,
                    max_size=max_size,
                )

            if atom_len > 0:
                capped = min(atom_len, len(artifact))
                size = capped
                file_type, extension, category = "MP4 / ISO Media Video", "mp4", "Media"
                confidence = 100 if ok and atom_len <= len(artifact) else 55

        if size <= 0:
            return None

        payload = artifact[:size]
        if not payload:
            return None

        return file_type, extension, category, confidence, payload

    def carve_target(
        self,
        job_id: str | None = None,
        target_path: str = "",
        output_base_dir: str = "./cases",
        scan_unallocated_only: bool = False,
    ) -> dict[str, Any]:
        start_time = time.time()
        active_job_id = (
            os.path.basename(job_id)
            if job_id
            else f"CASE-{int(start_time)}-{uuid.uuid4().hex[:6].upper()}"
        )

        case_dir = os.path.join(output_base_dir, active_job_id, "carved_evidence")
        dirs = {
            "Images": os.path.join(case_dir, "images"),
            "Documents": os.path.join(case_dir, "documents"),
            "Databases": os.path.join(case_dir, "databases"),
            "Network": os.path.join(case_dir, "network"),
            "Media": os.path.join(case_dir, "media"),
        }
        for d in dirs.values():
            os.makedirs(d, exist_ok=True)

        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target media '{target_path}' not found.")

        carved_catalog: list[dict[str, Any]] = []
        sample_map: list[dict[str, Any]] = []
        zeroed_blocks, structured_blocks, high_blocks = 0, 0, 0

        with open(target_path, "rb", buffering=0) as stream:
            target_bytes = self._get_target_size(stream.fileno(), target_path)
            scan_mode, scan_ranges, scan_ranges_manifest = self._resolve_scan_ranges(
                target_path,
                target_bytes,
                scan_unallocated_only,
            )

            for block_index, (offset, chunk) in enumerate(
                self._iter_entropy_blocks(stream, scan_ranges),
                start=1,
            ):
                entropy = self.calculate_entropy(chunk)
                classification = self.classify_entropy(entropy, chunk)

                if classification == "ZEROED_SANITIZED":
                    zeroed_blocks += 1
                elif classification == "STRUCTURED_UNCOMPRESSED":
                    structured_blocks += 1
                else:
                    high_blocks += 1

                if block_index <= 64:
                    sample_map.append(
                        {
                            "block_index": block_index,
                            "byte_offset": offset,
                            "entropy": entropy,
                            "classification": classification,
                        }
                    )

            idx = 1
            skip_until = -1

            for hit_offset in self._iter_candidate_offsets(stream, scan_ranges):
                if hit_offset < skip_until:
                    continue

                containing = self._range_for_offset(hit_offset, scan_ranges)
                if not containing:
                    continue

                _, range_end = containing
                carved = self._carve_at_offset(
                    stream,
                    target_path,
                    hit_offset,
                    target_bytes,
                    range_end,
                )

                if not carved:
                    skip_until = hit_offset + 1
                    continue

                file_type, extension, category, confidence, artifact_bytes = carved
                file_name = f"CARVED_{active_job_id}_{idx:04d}.{extension}"
                dest_path = os.path.join(dirs[category], file_name)

                with open(dest_path, "wb") as out_f:
                    out_f.write(artifact_bytes)

                source_space = (
                    "UNALLOCATED_SPACE"
                    if scan_mode == "UNALLOCATED_ONLY"
                    else "RAW_STREAM"
                )

                carved_catalog.append(
                    {
                        "file_id": f"CARVED_{active_job_id}_{idx:04d}",
                        "file_name": file_name,
                        "file_type": file_type,
                        "extension": extension,
                        "category": category,
                        "byte_offset_start": hit_offset,
                        "byte_offset_end": hit_offset + len(artifact_bytes),
                        "size_bytes": len(artifact_bytes),
                        "md5": hashlib.md5(artifact_bytes).hexdigest(),
                        "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                        "confidence_score": confidence,
                        "classification": "INTACT_VERIFIED"
                        if confidence >= 90
                        else "PARTIALLY_RECOVERED",
                        "source_space": source_space,
                        "exported_path": os.path.abspath(dest_path),
                    }
                )

                idx += 1
                skip_until = hit_offset + len(artifact_bytes)

        end_time = time.time()
        total_blocks = zeroed_blocks + structured_blocks + high_blocks
        exhaustion_pct = round(
            ((zeroed_blocks + high_blocks) / max(total_blocks, 1)) * 100.0,
            2,
        )

        audit_hash = hashlib.sha256(
            f"{active_job_id}:{target_path}:{target_bytes}:{len(carved_catalog)}:{end_time}".encode()
        ).hexdigest()

        return {
            "job_id": active_job_id,
            "target_path": target_path,
            "target_size_bytes": target_bytes,
            "scan_mode": scan_mode,
            "scan_ranges": scan_ranges_manifest,
            "scan_start_time": start_time,
            "scan_end_time": end_time,
            "live_files_detected": 0,
            "deleted_files_recovered": len(carved_catalog),
            "entropy_analysis": {
                "total_blocks_scanned": total_blocks,
                "zeroed_blocks": zeroed_blocks,
                "structured_blocks": structured_blocks,
                "compressed_or_encrypted_blocks": high_blocks,
                "carving_exhaustion_confidence_pct": exhaustion_pct,
                "sample_map": sample_map,
            },
            "carved_catalog": carved_catalog,
            "audit_hash": audit_hash,
        }


ForensicCarver = StreamCarver
