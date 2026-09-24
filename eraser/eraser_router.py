from dataclasses import asdict

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from core.database import (
    get_job,
    get_session,
    list_audit_ledger,
    log_audit_event,
)
from eraser.certificate_service import generate_nist_certificate
from eraser.drive_scanner import DriveScanner
from eraser.eraser_engine import SecureEraser

router = APIRouter()
scanner = DriveScanner()
eraser = SecureEraser()


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


class ErasureRequest(BaseModel):
    target_path: str = Field(min_length=1, max_length=4096)
    method: str = "NIST_CLEAR"
    verification_coverage_pct: float = Field(
        default=100.0,
        gt=0.0,
        le=100.0,
    )


@router.get("/drives")
def get_available_drives(
    user: dict = Depends(get_current_user),
):
    return {
        "status": "success",
        "drives": scanner.scan_drives(),
    }


@router.post("/execute")
@router.post("/execute/")
@router.post("/sanitize")
@router.post("/sanitize/")
def execute_erasure(
    request: ErasureRequest,
    user: dict = Depends(get_current_user),
):
    if user.get("role") not in {"Admin", "ErasureOperator"}:
        raise HTTPException(
            status_code=403,
            detail="Insufficient privileges for media destruction.",
        )

    try:
        result = eraser.sanitize_target(
            target_path=request.target_path,
            method=request.method,
            verification_coverage_pct=(request.verification_coverage_pct),
        )

        data = asdict(result)
        data["operation"] = "SANITIZATION"
        data["operator_username"] = user.get("username", "operator")
        data["status"] = "SANITIZED" if result.verified else "PARTIAL_FAILURE"

        log_audit_event(data)

        return {
            "status": "success" if result.verified else "failed",
            "data": data,
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

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc


@router.get("/ledger")
def get_ledger(
    user: dict = Depends(get_current_user),
):
    return {
        "status": "success",
        "data": list_audit_ledger(user.get("role", "Admin")),
    }


@router.get("/certificate/{job_id}")
def download_certificate(
    job_id: str,
    user: dict = Depends(get_current_user),
):
    if user.get("role") not in {"Admin", "ErasureOperator"}:
        raise HTTPException(
            status_code=403,
            detail="Insufficient privileges to download certificates.",
        )

    job = get_job(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Job not found.",
        )

    if job.get("operation") != "SANITIZATION":
        raise HTTPException(
            status_code=403,
            detail="Certificate unavailable for this operation.",
        )

    certificate = generate_nist_certificate(job)

    return Response(
        content=certificate,
        media_type="text/html",
        headers={
            "Content-Disposition": (f"inline; filename=NIST_Certificate_{job_id}.html")
        },
    )
