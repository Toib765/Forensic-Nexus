# Forensic Nexus project documentation

## 1. Overview

Forensic Nexus is a Linux-focused FastAPI application for two controlled
workflows:

1. **Sanitization**: discover a target, overwrite it using a selected method,
   verify the write, record an audit event, and generate a browser-readable
   certificate.
2. **Recovery**: scan a forensic image or approved device for supported file
   signatures, write carved artifacts into a case directory, hash the output,
   and record the recovery in the audit ledger.

The browser dashboard is served by the same FastAPI process. The API can also
be used directly with `curl` or another HTTP client.

> **Important:** Sanitization is destructive. Recovery and device access can
> expose sensitive evidence. Use disposable media or verified forensic copies,
> and follow the safety procedure in the root [README](../README.md).

## 2. Architecture

```text
Browser / API client
        |
        v
FastAPI application (main.py)
  |             |              |
  v             v              v
Auth router   Erasure router  Recovery router
  |             |              |
  v             v              v
SQLite       SecureEraser    StreamCarver
sessions     DriveScanner    FAT metadata support
users        certificates    signature validators
audit_vault  async jobs      async jobs
```

### Components

| Component | Responsibility |
| --- | --- |
| `main.py` | Creates the FastAPI app, initializes SQLite, mounts routers, serves the dashboard, and exposes `/cases`. |
| `core/auth_router.py` | Login, session lookup, and logout endpoints. |
| `core/database.py` | SQLite connection setup, password hashing, sessions, demo-user seeding, and audit persistence. |
| `core/job_manager.py` | Thread-safe in-memory state for background sanitization and carving jobs. |
| `eraser/drive_scanner.py` | Discovers Linux block devices and marks mounted/system devices. |
| `eraser/eraser_engine.py` | Validates targets, overwrites data, verifies selected offsets, and returns sanitization results. |
| `eraser/certificate_service.py` | Generates an HTML certificate from a completed sanitization audit record. |
| `recover/carver_engine.py` | Streams an image/device, finds file signatures, validates candidates, and writes carved artifacts. |
| `recover/fat_extractor.py` | Reads FAT/FAT32 allocation metadata for unallocated-only scans. |
| `recover/signatures.py` | Defines supported signatures and format-specific validation. |
| `static/` | Single-page dashboard assets (`index.html`, `app.js`, and `style.css`). |

### Persistence

The application creates `forensic_nexus.db` in the repository root. It
contains:

- `users`: username, PBKDF2 password hash, salt, role, and display name.
- `sessions`: bearer token, user, role, and creation time.
- `audit_vault`: sanitization and recovery history, verification details,
  hashes, status, operator, and recovered artifact count.

Background jobs are **not** persisted. The in-memory job store is cleared when
the process restarts, so it is intended for a single local instance rather
than a distributed deployment.

## 3. Roles and permissions

| Role | Drives | Sanitize | Recovery | Ledger | Certificates |
| --- | ---: | ---: | ---: | ---: | ---: |
| `ErasureOperator` | Yes | Yes | No | Yes | Yes |
| `ForensicInvestigator` | Yes | No | Yes | Yes | No |
| `Admin` | Yes | Yes | Yes | Yes | Yes |

Every protected request uses an `Authorization: Bearer <token>` header.
Tokens are stored in SQLite and expire according to
`FN_SESSION_TTL_SECONDS`.

## 4. Configuration

Configuration is read from environment variables at process startup:

| Variable | Default | Purpose |
| --- | --- | --- |
| `FN_ENV` | `development` | Controls the default demo-user behavior. `dev`, `development`, and `local` enable seeding. |
| `FN_ENABLE_DEMO_USERS` | Based on `FN_ENV` | Explicitly enables or disables demo-user seeding. Set `false` outside local development. |
| `FN_SESSION_TTL_SECONDS` | `28800` | Session lifetime in seconds (8 hours). |
| `FN_DB_TIMEOUT_SECONDS` | `5` | SQLite connection timeout. |
| `FN_DEMO_USER_ERASURE_USERNAME` / `_PASSWORD` | `toib` / `1234` | Local erasure-operator credentials. |
| `FN_DEMO_USER_FORENSIC_USERNAME` / `_PASSWORD` | `chethan` / `4321` | Local forensic-investigator credentials. |
| `FN_DEMO_USER_ADMIN_USERNAME` / `_PASSWORD` | `ujjwal` / `6969` | Local administrator credentials. |

The three demo credentials are development defaults only. Override them or
disable seeding before sharing the application or deploying it.

## 5. HTTP API

The interactive OpenAPI page is available at
`http://127.0.0.1:8000/docs` while the server is running.

### Authentication

| Method | Path | Access | Description |
| --- | --- | --- | --- |
| `POST` | `/api/v1/auth/login` | Public | Returns a bearer token for valid credentials. |
| `GET` | `/api/v1/auth/me` | Authenticated | Returns the current session. |
| `POST` | `/api/v1/auth/logout` | Authenticated | Revokes the current token. |

Trailing-slash variants are supported for these endpoints.

Login body:

```json
{"username": "toib", "password": "1234"}
```

### Sanitization

The `/api/v1/erasure` router is also available under the compatibility prefix
`/api/v1/eraser`.

| Method | Path | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/erasure/drives` | Authenticated | Lists discovered Linux drives and safety metadata. |
| `POST` | `/api/v1/erasure/execute` | Operator/Admin | Sanitizes a file, folder, image, or approved block-device target. |
| `GET` | `/api/v1/erasure/jobs/{job_id}` | Operator/Admin | Reads an asynchronous sanitization job. |
| `GET` | `/api/v1/erasure/ledger` | Authenticated | Lists audit records allowed for the current role. |
| `GET` | `/api/v1/erasure/certificate/{job_id}` | Operator/Admin | Downloads an HTML certificate for a sanitization record. |

Sanitization body:

```json
{
  "target_path": "./scratch/test.bin",
  "method": "NIST_CLEAR",
  "verification_coverage_pct": 100.0,
  "async_job": false
}
```

`verification_coverage_pct` must be greater than `0` and no more than `100`.
Set `async_job` to `true` for a queued background operation; the response
contains a job ID that can be polled.

### Recovery

| Method | Path | Access | Description |
| --- | --- | --- | --- |
| `POST` | `/api/v1/recovery/carve` | Investigator/Admin | Carves supported files into a directory under `./cases`. |
| `GET` | `/api/v1/recovery/carve/jobs/{job_id}` | Investigator/Admin | Reads an asynchronous carving job. |
| `GET` | `/api/v1/recovery/hex-inspect` | Authenticated | Reads a bounded hex preview of a carved artifact. |

Recovery body:

```json
{
  "job_id": "CASE-001",
  "target_path": "./evidence/seized.img",
  "output_dir": "./cases",
  "scan_unallocated_only": false,
  "async_job": false
}
```

Output paths are constrained to `./cases`. A `scan_unallocated_only` request
requires supported FAT/FAT32 allocation metadata; unsupported filesystems are
rejected rather than silently scanned as if they were FAT.

### Supported carved formats

The current signature database recognizes:

- JPEG and PNG images
- PDF documents
- ZIP containers and Office Open XML files (`docx`, `xlsx`, and `pptx`)
- MP4/ISO Base Media video
- SQLite databases

Carving is primarily intended for contiguous files. Fragmented-file
reconstruction is not currently provided.

## 6. Typical workflows

### Local development

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open the dashboard at `http://127.0.0.1:8000`.

### Sanitization

1. Inspect the target with `lsblk` when working with a device.
2. Confirm its model, serial, mount state, and intended scope.
3. Unmount disposable media before operating on it.
4. Select a method and verification coverage.
5. Run the operation and wait for a verified result.
6. Review the ledger and download the generated certificate.

### Recovery

1. Preserve and hash the original evidence.
2. Work from a copy whenever possible.
3. Choose a case identifier and output directory under `./cases`.
4. Run a normal or FAT/FAT32 unallocated-only carve.
5. Review artifact hashes and the audit record.
6. Use hex inspection only for artifacts inside the case output.

## 7. Testing and quality checks

Run the same checks used by CI:

```bash
python -m compileall core eraser recover main.py
python -m ruff check .
PYTHONPATH=. python -m pytest -q
```

The test suite covers erasure behavior, carving, certificates, asynchronous
jobs, and database sessions. `recover/real_loop_integration.py` is a manual
integration script and is not part of the normal pytest run because it may
need loop devices, filesystem tools, elevated device permissions, and
disposable media.

## 8. Security and operational notes

- Never assume a Linux device name such as `/dev/sda` identifies the intended
  media.
- Do not run the server with `sudo`; use the virtual environment and narrowly
  scoped permissions.
- Do not expose the development server or demo credentials to an untrusted
  network.
- Treat `./cases` as sensitive evidence and restrict filesystem permissions.
- The audit hash is an integrity checksum, not a private-key-backed signature.
- SQLite and the in-memory job store are designed for a single local node.
- The generated certificate is aligned with NIST SP 800-88 Rev. 1 wording; it
  is not an official NIST certification or validation.

## 9. Extension points

When adding a feature:

1. Put domain logic in `core/`, `eraser/`, or `recover/`, not in the static
   client.
2. Add or update a router schema and enforce the role at the endpoint.
3. Record destructive or evidence-handling operations in `audit_vault`.
4. Add focused tests under `tests/`.
5. Update this document and the root README if the public API or workflow
   changes.
6. Run compile, Ruff, and pytest checks before opening a pull request.
