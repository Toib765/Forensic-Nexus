import os
import sys
import io
import json
import zipfile

# Link sibling 'eraser' directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "eraser")))

from carver_engine import ForensicCarver
from eraser_engine import SecureEraser

def generate_seized_evidence_image(image_path: str):
    """Creates a raw test drive containing live files, deleted evidence, and unallocated slack."""
    # 1. Valid PNG Image (Deleted artifact in unallocated space)
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
        b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )

    # 2. Valid DOCX Container (Word Document with XML structure)
    docx_buf = io.BytesIO()
    with zipfile.ZipFile(docx_buf, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        zf.writestr("word/document.xml", '<w:document><w:body><w:p>Seized Data</w:p></w:body></w:document>')
    docx_bytes = docx_buf.getvalue()

    # 3. Minimal MP4 Video Container
    ftyp_box = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"
    mdat_box = b"\x00\x00\x00\x20mdat" + b"\x00" * 24
    mp4_bytes = ftyp_box + mdat_box

    # Write drive image layout
    with open(image_path, "wb") as f:
        f.write(b"\x00" * (1024 * 64))             # Simulated MBR/Partition Header
        f.write(png_bytes)                          # Injected deleted PNG
        f.write(b"\x00" * (1024 * 128))            # Unallocated sector gap
        f.write(docx_bytes)                         # Injected deleted DOCX
        f.write(b"\x55" * (1024 * 64))             # Structured noise
        f.write(mp4_bytes)                          # Injected deleted MP4 container
        f.write(b"\x00" * (1024 * 1024 * 2))        # Trailing clean space

def run_tests():
    test_img = "./seized_media.raw"
    generate_seized_evidence_image(test_img)

    carver = ForensicCarver()
    eraser = SecureEraser()

    print("=== TEST 1: Forensic Carving On Seized Media (Unallocated Parsing) ===")
    res = carver.carve_target(job_id="CASE-SEIZED-01", target_path=test_img, output_base_dir="./test_cases")
    
    print(f"Status: Success | Recovered Deleted Files: {res['deleted_files_recovered']}")
    print(f"Entropy Analysis Exhaustion: {res['entropy_analysis']['carving_exhaustion_confidence_pct']}%")
    
    for f in res["carved_catalog"]:
        print(f" -> [{f['classification']}] {f['file_name']} ({f['file_type']}) | Ext: .{f['extension']} | Score: {f['confidence_score']}% | Space: {f['source_space']}")

    assert res["deleted_files_recovered"] >= 3, "Failed to carve all injected artifacts"

    print("\n=== TEST 2: Post-Sanitization Zero-Recovery Assurance ===")
    eraser.sanitize(job_id="JOB-SANITIZE-01", target_path=test_img, method="NIST_CLEAR")
    
    post_wipe_res = carver.carve_target(job_id="CASE-POST-WIPE-01", target_path=test_img, output_base_dir="./test_cases")
    print(f"Post-Sanitization Files Carved: {post_wipe_res['deleted_files_recovered']}")
    print(f"Sanitized Zeroed Sectors: {post_wipe_res['entropy_analysis']['zeroed_blocks']} blocks")
    
    assert post_wipe_res["deleted_files_recovered"] == 0, "Security Failure: Files recovered from sanitized target"
    print("Verification Passed: 0 files recoverable.")

    if os.path.exists(test_img):
        os.remove(test_img)

if __name__ == "__main__":
    run_tests()

