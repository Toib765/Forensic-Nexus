import os
import sys
import subprocess
import time

# Link sibling eraser module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "eraser")))

from carver_engine import ForensicCarver
from eraser_engine import SecureEraser

TARGET = "/dev/loop10"
MOUNT_DIR = "/mnt/evidence_usb"

def run_cmd(cmd):
    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

print("[1/5] Formatting /dev/loop10 with FAT32...")
run_cmd(f"mkfs.vfat -F 32 -n 'EVID_USB' {TARGET}")

print("[2/5] Mounting /dev/loop10...")
os.makedirs(MOUNT_DIR, exist_ok=True)
run_cmd(f"mount {TARGET} {MOUNT_DIR}")

print("[3/5] Writing test evidence (PNG + ZIP) to /dev/loop10...")
# 1. Create a test PNG
png_raw = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
    b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)
with open(f"{MOUNT_DIR}/evidence_image.png", "wb") as f:
    f.write(png_raw)

# 2. Create secret zip
with open(f"{MOUNT_DIR}/classified.txt", "w") as f:
    f.write("CONFIDENTIAL EVIDENCE TOKEN: 12345")
run_cmd(f"zip -q -j {MOUNT_DIR}/suspect_data.zip {MOUNT_DIR}/classified.txt")
run_cmd(f"rm {MOUNT_DIR}/classified.txt")
run_cmd("sync")

print("[4/5] Deleting files from filesystem and unmounting drive...")
run_cmd(f"rm -rf {MOUNT_DIR}/*")
run_cmd("sync")
run_cmd(f"umount {MOUNT_DIR}")

print("\n[5/5] Executing Forensic Nexus Carver on /dev/loop10 raw sectors...")
carver = ForensicCarver()
eraser = SecureEraser()

manifest = carver.carve_target(
    job_id="AUTO-LOOP10",
    target_path=TARGET,
    output_base_dir="./cases"
)

print("\n" + "=" * 55)
print(f"[+] Scan Complete! Recovered Deleted Files: {manifest['deleted_files_recovered']}")
print(f"[+] Sector Coverage Exhaustion: {manifest['entropy_analysis']['carving_exhaustion_confidence_pct']}%")
print("=" * 55)

for f in manifest["carved_catalog"]:
    print(f" -> Found: {f['file_name']} | Type: {f['file_type']} | Score: {f['confidence_score']}%")
    print(f"    Path: {f['exported_path']}")

print("\n[*] Unpacking recovered ZIP payload to verify integrity:")
res = subprocess.run(
    "unzip -p cases/CASE_AUTO-LOOP10/carved_evidence/*/*.zip 2>/dev/null",
    shell=True,
    capture_output=True,
    text=True
)
print(f" -> Recovered Payload Content: '{res.stdout.strip()}'\n")

# Verify Sanitization
print("[*] Sanitizing /dev/loop10 via NIST_CLEAR (Zero-Fill)...")
eraser.sanitize(job_id="SANITIZE-AUTO-LOOP10", target_path=TARGET, method="NIST_CLEAR")

print("[*] Running post-wipe carver check...")
post_res = carver.carve_target(
    job_id="POST-WIPE-AUTO",
    target_path=TARGET,
    output_base_dir="./cases"
)
print(f"[+] Post-Wipe Recovered Count: {post_res['deleted_files_recovered']}")
if post_res['deleted_files_recovered'] == 0:
    print("[✔] VERIFICATION PASSED: Media completely sanitized (0 artifacts left).")
