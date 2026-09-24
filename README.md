# Forensic Nexus

Forensic Nexus is a Linux-focused platform that combines secure media sanitization, forensic file carving, audit logging, and certificate generation in one web application.

> Built for Smart India Hackathon 2026, Problem Statement SIH25149, under the Blockchain & Cybersecurity theme.

## What it provides

- **Secure erasure** of approved files, folders, raw images, and block-device targets.
- **Verification** through post-write read-back checks.
- **Forensic carving** for common contiguous file signatures, including PNG, JPEG, PDF, Office/ZIP, SQLite, PCAP, and MP4.
- **Drive discovery** with protection for mounted and system devices.
- **SQLite audit ledger** for sanitization and recovery activity.
- **Browser certificates** for completed sanitization jobs.
- **Role-based sessions** for operators, investigators, and administrators.
- **Web dashboard** for drive selection, recovery, sanitization, ledger review, and artifact inspection.

The certificate wording is intentionally **NIST SP 800-88 Rev. 1 aligned**. This project is not an official NIST certification or validation product.

## Safety warning

This software can permanently destroy data. Use it only on disposable test media or verified forensic copies.

Before touching a block device on Linux:

```bash
lsblk -o NAME,PATH,SIZE,RM,TYPE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL
```

Confirm the device by its model and serial number. Never assume that `/dev/sda` or another device name is safe. Do not select a mounted system device. Do not run the server with `sudo`; use the project virtual environment and grant narrowly scoped device permissions only when required.

For recovery, prefer an image copy (`.raw` or `.img`) instead of a live device:

1. Acquire or create the image.
2. Hash and preserve the original.
3. Work on a copy.
4. Store recovered artifacts in a separate case directory.

## Project structure

```text
Forensic-Nexus/
├── main.py
├── requirements.txt
├── pyproject.toml
├── pytest.ini
├── .github/workflows/ci.yml
├── core/
│   ├── database.py
│   └── auth_router.py
├── eraser/
│   ├── eraser_engine.py
│   ├── drive_scanner.py
│   ├── certificate_service.py
│   ├── eraser_router.py
│   └── test_runner.py
├── recover/
│   ├── carver_engine.py
│   ├── atom_carver.py
│   ├── entropy_scanner.py
│   ├── fat_extractor.py
│   ├── signatures.py
│   ├── recovery_router.py
│   ├── test_carver.py
│   └── real_loop_integration.py
├── static/
│   ├── index.html
│   ├── app.js
│   └── style.css
└── tests/
    └── test_eraser.py
```

## Requirements

- Linux host
- Python 3.11 or newer
- Python packages from `requirements.txt`
- `lsblk` for drive discovery
- Optional filesystem tools such as `mkfs.exfat` for disposable-media testing

## Setup

```bash
git clone https://github.com/Toib765/Forensic-Nexus.git
cd Forensic-Nexus
git checkout feature/improvements
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

For Fish:

```fish
source venv/bin/activate.fish
```

## Run the web application

From the repository root, with the virtual environment active:

```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Development reload mode:

```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Open:

- Dashboard: `http://127.0.0.1:8000`
- FastAPI documentation: `http://127.0.0.1:8000/docs`

Do not use `sudo python main.py`. `sudo` uses root's system Python instead of the virtual environment and can create root-owned files.

## Demo accounts

Demo users are intended for local development only and are seeded only when enabled.

- `FN_ENABLE_DEMO_USERS=true|false` controls whether seed users are created.
- Default behavior: enabled only when `FN_ENV` is `development`/`dev`/`local`; disabled otherwise.
- Session lifetime is controlled by `FN_SESSION_TTL_SECONDS` (default `28800`, 8 hours).

Optional credential overrides:

- `FN_DEMO_USER_ERASURE_USERNAME` / `FN_DEMO_USER_ERASURE_PASSWORD`
- `FN_DEMO_USER_FORENSIC_USERNAME` / `FN_DEMO_USER_FORENSIC_PASSWORD`
- `FN_DEMO_USER_ADMIN_USERNAME` / `FN_DEMO_USER_ADMIN_PASSWORD`

Development defaults (when demo seeding is enabled) are: `toib/1234`, `chethan/4321`, and `ujjwal/6969`.
Never keep these defaults in shared, hosted, or production deployments.

## Safe test workflow

### Synthetic tests

Run the automated suite:

```bash
python -m compileall core eraser recover main.py
python -m pytest -q
python -m ruff check .
```

Run the synthetic carver demo from the repository root:

```bash
python -m recover.test_carver
```

The real-loop integration script is intentionally not collected by pytest. It can require root access, loop devices, filesystem tools, and a disposable device:

```bash
python recover/real_loop_integration.py
```

Use it only when you understand the commands it executes.

### Disposable image testing

A small image is safer than a real disk:

```bash
mkdir -p scratch
truncate -s 128M scratch/recovery-test.img
mkfs.vfat -F 32 scratch/recovery-test.img
```

Mount it with `udisksctl`, add disposable files, delete a test file, unmount it, and point the recovery UI at the image file. Clean up afterward:

```bash
rm -rf scratch
```

### Disposable USB testing

If you deliberately test real hardware, verify the model and serial, create a small test partition, and use only that partition. Do not select the whole disk unless you intend to erase the partition table and all contents. Always unmount the partition before recovery or sanitization.

For FAT/FAT32 targets, `scan_unallocated_only=true` now uses FAT allocation metadata to carve only unallocated ranges.
For non-FAT or unsupported filesystems, unallocated-only requests are rejected explicitly instead of silently falling back.

## API examples

Start the server first, then log in:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"toib","password":"1234"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["data"]["token"])')
```

List detected devices:

```bash
curl -s http://127.0.0.1:8000/api/v1/erasure/drives \
  -H "Authorization: Bearer $TOKEN"
```

Sanitize a disposable file:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/erasure/execute \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target_path":"./scratch/test.bin","method":"NIST_CLEAR","verification_coverage_pct":100.0}'
```

Carve a forensic image:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/recovery/carve \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"job_id":"CASE-001","target_path":"./evidence/seized.img","output_dir":"./cases","scan_unallocated_only":false}'
```

## CI

GitHub Actions runs on pushes and pull requests. It installs dependencies, compiles the application, runs Ruff, and runs pytest. The workflow sets the repository root on `PYTHONPATH` so package imports such as `from eraser.eraser_engine import SecureEraser` work consistently in CI and locally.

## Known limitations

- Linux-only device discovery and raw-device workflows.
- Mobile/ADB storage erasure is not implemented.
- Flash storage recovery is not guaranteed; controllers, TRIM, and garbage collection can remove deleted data.
- Recovery currently favors contiguous files and does not reconstruct fragmented files.
- Unallocated-only carving currently supports FAT/FAT32 metadata parsing; unsupported filesystems are rejected in unallocated-only mode.
- Confidence scoring is stronger for some formats than others.
- The audit hash is an integrity checksum, not a private-key-backed digital signature.
- SQLite is suitable for a single-node demo, not concurrent multi-instance deployment.
- Demo credentials and local session storage require hardening for production.

## License

See `LICENSE`. Review the project licensing terms before redistributing the software.
