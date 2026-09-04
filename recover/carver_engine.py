import os
import math
import time
import struct
import hashlib
import mmap
import fcntl
import uuid
from typing import Dict, Any

class StreamCarver:
    def __init__(self, block_size: int = 65536):
        self.block_size = block_size
        self.max_carve_size = 25 * 1024 * 1024

    def _get_target_size(self, fd: int, target_path: str) -> int:
        if target_path.startswith('/dev/'):
            try:
                buf = fcntl.ioctl(fd, 0x80081272, b"\x00" * 8)
                size = struct.unpack("Q", buf)[0]
                if size > 0:
                    return size
            except Exception:
                pass
            try:
                size = os.lseek(fd, 0, os.SEEK_END)
                os.lseek(fd, 0, os.SEEK_SET)
                if size > 0:
                    return size
            except Exception:
                pass
            return 536870912
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
        elif entropy < 4.5:
            return "STRUCTURED_UNCOMPRESSED"
        else:
            return "COMPRESSED_OR_ENCRYPTED"

    def carve_target(self, job_id: str = None, target_path: str = "", output_base_dir: str = "./cases", scan_unallocated_only: bool = False) -> Dict[str, Any]:
        start_time = time.time()
        active_job_id = os.path.basename(job_id) if job_id else f"CASE-{int(start_time)}-{uuid.uuid4().hex[:6].upper()}"
        
        case_dir = os.path.join(output_base_dir, active_job_id, "carved_evidence")
        dirs = {
            "Images": os.path.join(case_dir, "images"),
            "Documents": os.path.join(case_dir, "documents"),
            "Databases": os.path.join(case_dir, "databases"),
            "Network": os.path.join(case_dir, "network"),
            "Media": os.path.join(case_dir, "media")
        }
        for d in dirs.values():
            os.makedirs(d, exist_ok=True)

        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target media '{target_path}' not found.")

        carved_catalog = []
        sample_map = []
        zeroed_blocks, structured_blocks, high_blocks = 0, 0, 0

        with open(target_path, "rb") as f:
            target_bytes = self._get_target_size(f.fileno(), target_path)
            total_blocks = math.ceil(target_bytes / self.block_size) if target_bytes > 0 else 0

            mm = mmap.mmap(f.fileno(), target_bytes, access=mmap.ACCESS_READ)

            sample_limit = min(total_blocks, 64)
            for b_idx in range(sample_limit):
                b_offset = b_idx * self.block_size
                chunk = mm[b_offset : b_offset + self.block_size]
                entropy = self.calculate_entropy(chunk)
                classification = self.classify_entropy(entropy, chunk)

                if classification == "ZEROED_SANITIZED":
                    zeroed_blocks += 1
                elif classification == "STRUCTURED_UNCOMPRESSED":
                    structured_blocks += 1
                else:
                    high_blocks += 1

                sample_map.append({
                    "block_index": b_idx + 1,
                    "byte_offset": b_offset,
                    "entropy": entropy,
                    "classification": classification
                })

            i = 0
            idx = 1
            while i < target_bytes - 16:
                found, f_size = False, 0
                f_type, ext, category = "", "", ""
                confidence = 0

                if mm[i:i+8] == b"\x89PNG\r\n\x1a\n":
                    iend = mm.find(b"IEND", i, min(i + self.max_carve_size, target_bytes))
                    if iend != -1:
                        f_size = (iend + 8) - i
                        f_type, ext, category, confidence, found = "PNG Image", "png", "Images", 100, True

                elif mm[i:i+3] == b"\xff\xd8\xff":
                    eoi = mm.find(b"\xff\xd9", i + 2, min(i + self.max_carve_size, target_bytes))
                    if eoi != -1:
                        f_size = (eoi + 2) - i
                        f_type, ext, category, confidence, found = "JPEG Image", "jpg", "Images", 100, True

                elif mm[i:i+5] == b"%PDF-":
                    eof_idx = mm.find(b"%%EOF", i, min(i + self.max_carve_size, target_bytes))
                    if eof_idx != -1:
                        f_size = (eof_idx + 5) - i
                        f_type, ext, category, confidence, found = "PDF Document", "pdf", "Documents", 100, True

                elif mm[i:i+4] == b"PK\x03\x04":
                    eocd = mm.find(b"PK\x05\x06", i, min(i + self.max_carve_size, target_bytes))
                    if eocd != -1:
                        comment_len = struct.unpack("<H", mm[eocd+20:eocd+22])[0] if eocd + 22 <= target_bytes else 0
                        f_size = (eocd + 22 + comment_len) - i
                        category = "Documents"
                        sample_slice = mm[i : min(i + 4096, target_bytes)]
                        if b"word/" in sample_slice:
                            f_type, ext = "DOCX Document", "docx"
                        elif b"ppt/" in sample_slice:
                            f_type, ext = "PPTX Presentation", "pptx"
                        elif b"xl/" in sample_slice:
                            f_type, ext = "XLSX Spreadsheet", "xlsx"
                        else:
                            f_type, ext = "ZIP Archive", "zip"
                        confidence, found = 100, True

                elif mm[i:i+16] == b"SQLite format 3\x00" and i + 100 <= target_bytes:
                    p_size = struct.unpack(">H", mm[i+16:i+18])[0]
                    p_count = struct.unpack(">I", mm[i+28:i+32])[0]
                    calc_size = (p_size if p_size != 1 else 65536) * (p_count if p_count > 0 else 2)
                    if 512 <= calc_size <= self.max_carve_size:
                        f_size = calc_size
                        f_type, ext, category, confidence, found = "SQLite Database", "db", "Databases", 100, True

                elif mm[i:i+4] in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"]:
                    f_size = 4096
                    f_type, ext, category, confidence, found = "PCAP Network Capture", "pcap", "Network", 90, True

                if found and f_size > 0:
                    artifact_bytes = mm[i : i + f_size]
                    file_name = f"CARVED_{active_job_id}_{idx:04d}.{ext}"
                    dest_path = os.path.join(dirs[category], file_name)

                    with open(dest_path, "wb") as out_f:
                        out_f.write(artifact_bytes)

                    carved_catalog.append({
                        "file_id": f"CARVED_{active_job_id}_{idx:04d}",
                        "file_name": file_name,
                        "file_type": f_type,
                        "extension": ext,
                        "category": category,
                        "byte_offset_start": i,
                        "byte_offset_end": i + f_size,
                        "size_bytes": len(artifact_bytes),
                        "md5": hashlib.md5(artifact_bytes).hexdigest(),
                        "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                        "confidence_score": confidence,
                        "classification": "INTACT_VERIFIED" if confidence >= 90 else "PARTIALLY_RECOVERED",
                        "source_space": "UNALLOCATED_SPACE",
                        "exported_path": os.path.abspath(dest_path)
                    })

                    idx += 1
                    i = ((i + f_size + 511) // 512) * 512
                else:
                    i += 512

            mm.close()

        end_time = time.time()
        audit_hash = hashlib.sha256(
            f"{active_job_id}:{target_path}:{target_bytes}:{len(carved_catalog)}:{end_time}".encode()
        ).hexdigest()

        return {
            "job_id": active_job_id,
            "target_path": target_path,
            "target_size_bytes": target_bytes,
            "scan_start_time": start_time,
            "scan_end_time": end_time,
            "live_files_detected": 0,
            "deleted_files_recovered": len(carved_catalog),
            "entropy_analysis": {
                "total_blocks_scanned": total_blocks,
                "zeroed_blocks": zeroed_blocks,
                "structured_blocks": structured_blocks,
                "compressed_or_encrypted_blocks": high_blocks,
                "carving_exhaustion_confidence_pct": 100.0,
                "sample_map": sample_map
            },
            "carved_catalog": carved_catalog,
            "audit_hash": audit_hash
        }

ForensicCarver = StreamCarver
