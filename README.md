Forensic Nexus
An integrated secure data erasure and forensic file recovery platform.
Built for Smart India Hackathon 2026 — Problem Statement SIH25149,
posed by the National Technical Research Organisation (NTRO), under the
Blockchain & Cybersecurity theme.
> Most tools do one of two things: securely destroy data, or recover deleted
> data. Investigators end up juggling separate tools for sanitization and
> forensic recovery. Forensic Nexus puts both in one platform with a shared
> audit trail, so the same evidence lifecycle — seize, image, analyze,
> sanitize, certify — can happen in one place.
---
What it does
Secure Erasure — wipes block devices, raw disk images, and individual
files/folders using NIST SP 800-88 Clear (1-pass zero-fill), a 1-pass
random overwrite, or a 3-pass DoD 5220.22-M-style pattern. Every job is
verified with a real post-overwrite read-back, not just assumed to have
worked.
Forensic Recovery / Carving — scans a raw image or device for
recoverable files (JPEG, PNG, PDF, DOCX/XLSX/PPTX/ZIP, SQLite, PCAP, MP4)
without relying on filesystem metadata, and can scope a scan to just the
unallocated space on a FAT-formatted source.
Audit ledger & certificates — every erasure job is logged to a
persistent SQLite ledger and can be exported as a sanitization certificate
(open the download in a browser, print/save as PDF).
Role-based access — real session-token auth (salted+hashed passwords,
server-side sessions) gates who can trigger erasure vs. who can only view
the audit ledger.
Web dashboard — a single-page frontend for drive selection, job
progress, and a hex viewer over recovered artifacts.
Project structure
```
Forensic Nexus/
├── main.py                  # App entrypoint — mounts all routers, serves the frontend
├── requirements.txt
├── core/
│   ├── database.py          # SQLite: users, sessions, audit ledger
│   └── auth\_router.py       # /api/v1/auth — login, session, logout
├── eraser/
│   ├── eraser\_engine.py     # SecureEraser — the actual overwrite + verification logic
│   ├── drive\_scanner.py     # Detects attached block devices, flags system disks
│   ├── certificate\_service.py  # Renders the sanitization certificate
│   ├── eraser\_router.py     # /api/v1/erasure — execute, drives, ledger, certificate
│   └── test\_runner.py       # Engine test suite
├── recover/
│   ├── carver\_engine.py     # StreamCarver — signature-based carving engine
│   ├── atom\_carver.py       # MP4/ISO-media box-chain parser
│   ├── entropy\_scanner.py   # Block-level entropy classification
│   ├── fat\_extractor.py     # FAT32 boot sector / directory / unallocated-space parsing
│   ├── signatures.py        # Structural validators (PNG/ZIP/PDF/SQLite)
│   ├── recovery\_router.py   # /api/v1/recovery — carve, hex-inspect
│   └── test\_carver.py       # Carving engine test suite
└── static/                  # Frontend (index.html, app.js, style.css)
```
Getting started
```bash
git clone https://github.com/<your-username>/forensic-nexus.git
cd forensic-nexus

python3 -m venv venv
source venv/bin/activate      # Windows: venv\\Scripts\\activate

pip install -r requirements.txt

python3 main.py
```
The app comes up at `http://127.0.0.1:8000`. Some erasure operations (raw
block devices) need permissions your user account may not have by default —
if you hit a permission error there, that's the OS restricting raw device
access, not a bug.
Demo login
Three accounts are pre-seeded on first run (`core/database.py`):
Username	Password	Role
`toib`	`1234`	ErasureOperator
`shaurya`	`4321`	ForensicInvestigator
`ujjwal`	`6969`	Admin
These are placeholder demo credentials — change them (or add real
registration) before this ever runs anywhere besides your own machine.
Using it
Everything goes through the API the frontend also uses. A quick end-to-end
example with `curl`:
```bash
# 1. Log in, grab a session token
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"toib","password":"1234"}' | python3 -c "import sys,json; print(json.load(sys.stdin)\['data']\['token'])")

# 2. See what drives are detected
curl -s http://127.0.0.1:8000/api/v1/erasure/drives \\
  -H "Authorization: Bearer $TOKEN"

# 3. Sanitize a target (a file, folder, or /dev/... device you actually intend to wipe)
curl -s -X POST http://127.0.0.1:8000/api/v1/erasure/execute \\
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"target\_path": "./scratch/old\_report.docx", "method": "DOD\_3PASS", "verification\_coverage\_pct": 100.0}'

# 4. Carve a raw image for recoverable files
curl -s -X POST http://127.0.0.1:8000/api/v1/recovery/carve \\
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"job\_id": "CASE-001", "target\_path": "./evidence/seized.img"}'
```
Full interactive docs (every route, request/response shape) are auto-generated
by FastAPI at `http://127.0.0.1:8000/docs` once the app is running.
A note on `target\_path`: for recovery, point it at a forensic image
(`.raw`/`.img`), not a live mounted device — image first, hash the image,
work off the copy. That's what preserves the original evidence.
Running the tests
```bash
cd eraser \&\& python3 test\_runner.py
cd ../recover \&\& python3 test\_carver.py
```
Both suites build their own synthetic test data and clean up after
themselves — no real device or fixture files needed.
Known limitations / Roadmap
Being upfront about what's not here yet, rather than let it be a surprise:
Mobile/ADB storage erasure isn't implemented. The engine currently
handles block devices, raw images, and files/folders on the local
filesystem only.
Linux-only. Block-device paths, `lsblk`, and the FAT extractor all
assume a Linux host. No Windows/macOS device path support yet.
Recovery confidence scoring is partial. PNG, ZIP/Office, and MP4
candidates are validated against real structural checks; JPEG/PDF/PCAP
confidence is currently based on whether a footer was found, not a full
structural parse. `signatures.py` has more rigorous validators
(`validate\_pdf\_structure`, etc.) that aren't fully wired into the carving
loop yet.
No fragmented-file reconstruction. Carving currently recovers
contiguous files; a file split across non-adjacent regions of the disk
isn't reassembled.
Audit hash is a checksum, not a signature. `audit\_hash` is a SHA-256
digest over a job's metadata — it detects tampering with that specific
record, but isn't a cryptographic signature backed by a private key. A
proper chain-of-custody signing scheme is a natural next step.
Single-node SQLite for the audit ledger — fine for a demo/single
deployment, would need a proper database for multi-instance use.
Contributions and issues welcome — this is very much still evolving.
License
Not yet decided — add one before treating this as reusable by others
(MIT is a reasonable default for a hackathon project if you want it
permissive).
