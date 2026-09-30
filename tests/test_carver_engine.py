from pathlib import Path

import pytest

from recover import carver_engine
from recover.carver_engine import StreamCarver

PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)


def test_full_scan_sets_raw_stream_source_space(tmp_path: Path):
    target = tmp_path / "target.raw"
    target.write_bytes(b"A" * 70000 + PNG_BYTES + b"\x00" * 70000)

    result = StreamCarver(block_size=4096, scan_chunk_size=8192).carve_target(
        job_id="CASE-RAW",
        target_path=str(target),
        output_base_dir=str(tmp_path),
        scan_unallocated_only=False,
    )

    assert result["scan_mode"] == "FULL_RAW_STREAM"
    assert result["scan_ranges"] == [{"start_byte": 0, "end_byte": target.stat().st_size}]
    assert result["deleted_files_recovered"] >= 1
    assert result["carved_catalog"][0]["source_space"] == "RAW_STREAM"
    assert result["entropy_analysis"]["carving_exhaustion_confidence_pct"] < 100.0
    assert len(result["entropy_analysis"]["sample_map"]) <= 64


def test_unallocated_only_rejects_unsupported_filesystem(tmp_path: Path):
    target = tmp_path / "unsupported.img"
    target.write_bytes(b"not-a-fat-filesystem" + b"\x00" * 4096)

    with pytest.raises(ValueError, match="FAT/FAT32"):
        StreamCarver().carve_target(
            job_id="CASE-UNALLOC",
            target_path=str(target),
            output_base_dir=str(tmp_path),
            scan_unallocated_only=True,
        )


def test_unallocated_only_uses_selected_ranges(monkeypatch, tmp_path: Path):
    prefix = b"A" * 8192
    target = tmp_path / "fat.img"
    target.write_bytes(prefix + PNG_BYTES + b"\x00" * 4096)

    class FakeFatExtractor:
        def __init__(self, target_path: str):
            self.target_path = target_path

        def parse_boot_sector(self):
            return True

        def get_cluster_allocation_map(self):
            start = len(prefix)
            end = len(prefix) + len(PNG_BYTES) + 512
            return [], [(start, end)]

    monkeypatch.setattr(carver_engine, "FatExtractor", FakeFatExtractor)

    result = StreamCarver(block_size=1024, scan_chunk_size=2048).carve_target(
        job_id="CASE-RANGE",
        target_path=str(target),
        output_base_dir=str(tmp_path),
        scan_unallocated_only=True,
    )

    assert result["scan_mode"] == "UNALLOCATED_ONLY"
    assert result["scan_ranges"][0]["start_byte"] == len(prefix)
    assert result["deleted_files_recovered"] >= 1
    assert result["carved_catalog"][0]["source_space"] == "UNALLOCATED_SPACE"


def test_sqlite_truncated_data_is_not_high_confidence(tmp_path: Path):
    target = tmp_path / "sqlite.raw"
    header = bytearray(100)
    header[:16] = b"SQLite format 3\x00"
    header[16:18] = (4096).to_bytes(2, "big")
    header[28:32] = (1024).to_bytes(4, "big")

    target.write_bytes(bytes(header) + b"\x00" * 1024)

    result = StreamCarver(block_size=512, scan_chunk_size=1024).carve_target(
        job_id="CASE-SQLITE",
        target_path=str(target),
        output_base_dir=str(tmp_path),
    )

    sqlite_items = [
        item for item in result["carved_catalog"] if item["file_type"].startswith("SQLite")
    ]
    assert sqlite_items
    assert all(item["confidence_score"] < 90 for item in sqlite_items)
