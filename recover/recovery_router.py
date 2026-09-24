from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

from core.database import get_session, log_audit_event
from core.job_manager import job_store
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
    async_job: bool = False


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


def _log_recovery_audit(request: CarveRequest, result: dict, username: str):
    log_audit_event(
        {
            "job_id": result["job_id"],
            "operation": "CARVE",
            "target_path": result["target_path"],
            "target_type": (
                "BLOCK_DEVICE" if request.target_path.startswith("/dev/") else "FILE"
            ),
            "method": "RAW_STREAM_CARVE",
            "bytes_processed": result["target_size_bytes"],
            "start_time": result["scan_start_time"],
            "end_time": result["scan_end_time"],
            "verified": True,
            "verification_method": "SHA-256 artifact hashing",
            "verification_coverage_pct": 100.0,
            "audit_hash": result["audit_hash"],
            "status": f"COMPLETED ({result['deleted_files_recovered']} recovered)",
            "recovered_count": result["deleted_files_recovered"],
            "operator_username": username,
        }
    )


def _run_carve_job(job_id: str, request: CarveRequest, output_dir: str, username: str):
    job_store.mark_running(job_id)
    try:
        result = carver.carve_target(
            job_id=request.job_id,
            target_path=request.target_path,
            output_base_dir=output_dir,
            scan_unallocated_only=request.scan_unallocated_only,
        )
        _log_recovery_audit(request, result, username)
        job_store.mark_success(job_id, result)
    except Exception as exc:
        job_store.mark_failed(job_id, str(exc))


@router.post("/carve")
def execute_carve(
    request: CarveRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(get_current_user),
):
    if user.get("role") not in {
        "Admin",
        "ForensicInvestigator",
    }:
        raise HTTPException(
            status_code=403,
            detail="Insufficient privileges for forensic carving.",
        )

    output_dir = str(safe_output_dir(request.output_dir))

    if request.async_job:
        async_job = job_store.create(
            operation="CARVE",
            requested_by=user.get("username", "investigator"),
            context={
                "target_path": request.target_path,
                "scan_unallocated_only": request.scan_unallocated_only,
            },
        )
        background_tasks.add_task(
            _run_carve_job,
            async_job["job_id"],
            request,
            output_dir,
            user.get("username", "investigator"),
        )
        return {"status": "accepted", "data": async_job}

    try:
        result = carver.carve_target(
            job_id=request.job_id,
            target_path=request.target_path,
            output_base_dir=output_dir,
            scan_unallocated_only=request.scan_unallocated_only,
        )

        _log_recovery_audit(request, result, user.get("username", "investigator"))

        return {
            "status": "success",
            "data": result,
        }

    except PermissionError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
        ) from exc

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to read evidence source: {exc!s}",
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Deep carving failed: {exc!s}",
        ) from exc


@router.get("/carve/jobs/{job_id}")
def get_carve_job_status(job_id: str, user: dict = Depends(get_current_user)):
    if user.get("role") not in {"Admin", "ForensicInvestigator"}:
        raise HTTPException(status_code=403, detail="Insufficient privileges.")

    status = job_store.get(job_id)
    if not status or status.get("operation") != "CARVE":
        raise HTTPException(status_code=404, detail="Job not found.")

    return {"status": "success", "data": status}


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
