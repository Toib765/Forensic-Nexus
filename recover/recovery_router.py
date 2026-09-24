from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

from core.database import get_session, log_audit_event
from recover.carver_engine import StreamCarver

router = APIRouter()
carver = StreamCarver()
CASES_ROOT = Path("./cases").resolve()


def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authentication token.",
        )

    token = authorization.split(" ", 1)[1].strip()
    user = get_session(token)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Session expired or invalid.",
        )

    return user


class CarveRequest(BaseModel):
    job_id: str | None = Field(default=None, max_length=128)
    target_path: str = Field(min_length=1, max_length=4096)
    output_dir: str = Field(default="./cases", max_length=4096)
    scan_unallocated_only: bool = False


def safe_output_dir(value: str) -> Path:
    requested = Path(value).resolve()

    if requested != CASES_ROOT and CASES_ROOT not in requested.parents:
        raise HTTPException(
            status_code=400,
            detail="output_dir must remain inside ./cases.",
        )

    requested.mkdir(parents=True, exist_ok=True)
    return requested


def safe_component(value: str, label: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {label}.",
        )

    return value


@router.post("/carve")
def execute_carve(
    request: CarveRequest,
    user: dict = Depends(get_current_user),
):
    if user.get("role") not in {"Admin", "ForensicInvestigator"}:
        raise HTTPException(
            status_code=403,
            detail="Insufficient privileges for forensic carving.",
        )

    try:
        output_dir = safe_output_dir(request.output_dir)

        result = carver.carve_target(
            job_id=request.job_id,
            target_path=request.target_path,
            output_base_dir=str(output_dir),
            scan_unallocated_only=request.scan_unallocated_only,
        )

        log_audit_event(
            {
                "job_id": result["job_id"],
                "operation": "CARVE",
                "target_path": result["target_path"],
                "target_type": (
                    "BLOCK_DEVICE"
                    if request.target_path.startswith("/dev/")
                    else "FILE"
                ),
                "method": "RAW_STREAM_CARVE",
                "bytes_processed": result["target_size_bytes"],
                "start_time": result["scan_start_time"],
                "end_time": result["scan_end_time"],
                "verified": True,
                "verification_method": "SHA-256 artifact hashing",
                "verification_coverage_pct": 100.0,
                "audit_hash": result["audit_hash"],
                "status": (
                    f"COMPLETED ({result['deleted_files_recovered']} recovered)"
                ),
                "recovered_count": result["deleted_files_recovered"],
                "operator_username": user.get("username", "investigator"),
            }
        )

        return {
            "status": "success",
            "data": result,
        }

    except HTTPException:
        raise

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Deep carving failed: {exc}",
        ) from exc


@router.get("/hex-inspect")
def inspect_hex(
    case_id: str = Query(...),
    file_name: str = Query(...),
    category: str = Query(...),
    length: int = Query(512, ge=1, le=1024 * 1024),
    user: dict = Depends(get_current_user),
):
    case_id = safe_component(case_id, "case_id")
    file_name = safe_component(file_name, "file_name")
    category = safe_component(category, "category")

    case_root = (CASES_ROOT / case_id / "carved_evidence").resolve()

    target = (case_root / category.lower() / file_name).resolve()

    if CASES_ROOT not in target.parents or not target.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"Artifact '{file_name}' not found.",
        )

    with target.open("rb") as stream:
        raw = stream.read(length)

    lines = []

    for offset in range(0, len(raw), 16):
        chunk = raw[offset : offset + 16]

        lines.append(
            {
                "offset": f"0x{offset:08X}",
                "hex": " ".join(f"{byte:02X}" for byte in chunk).ljust(48),
                "ascii": "".join(
                    chr(byte) if 32 <= byte <= 126 else "." for byte in chunk
                ),
            }
        )

    return {
        "status": "success",
        "hex_lines": lines,
    }
