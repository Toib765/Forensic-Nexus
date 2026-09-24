import os
import time
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Header
from fastapi.responses import Response
from pydantic import BaseModel, Field

from core.database import log_audit_event, get_job, list_audit_ledger, get_session
from eraser.drive_scanner import DriveScanner
from eraser.eraser_engine import SecureEraser
from eraser.certificate_service import generate_nist_certificate

router = APIRouter()
scanner = DriveScanner()
eraser = SecureEraser()


def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authentication token.")
    token = authorization.split(" ", 1)[1]
    user = get_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid.")
    return user


class ErasureRequest(BaseModel):
    target_path: str
    method: str = "NIST_CLEAR"
    verification_coverage_pct: float = Field(default=100.0, gt=0.0, le=100.0)


@router.get("/drives")
def get_available_drives(user: dict = Depends(get_current_user)):
    try:
        return {"drives": scanner.scan_drives()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Drive Scan Error: {str(e)}")


@router.post("/execute")
@router.post("/execute/")
@router.post("/sanitize")
@router.post("/sanitize/")
def execute_erasure(req: ErasureRequest, user: dict = Depends(get_current_user)):
    if user.get("role") not in ["Admin", "ErasureOperator"]:
        raise HTTPException(status_code=403, detail="Insufficient privileges for media destruction.")

    try:
        res = eraser.sanitize_target(
            target_path=req.target_path,
            method=req.method,
            verification_coverage_pct=req.verification_coverage_pct,
        )

        job_data = {
            "job_id": res.job_id,
            "operation": "SANITIZATION",
            "target_path": res.target_path,
            "target_type": res.target_type,
            "method": res.method,
            "bytes_processed": res.bytes_processed,
            "start_time": res.start_time,
            "end_time": res.end_time,
            "verified": res.verified,
            "verification_method": res.verification_method,
            "verification_coverage_pct": res.verification_coverage_pct,
            "audit_hash": res.audit_hash,
            "status": "SANITIZED (VERIFIED)" if res.verified else "VERIFICATION_FAILED",
            "operator_username": user.get("username", "operator"),
        }

        log_audit_event(job_data)
        return {"status": "success" if res.verified else "failed", "data": job_data}

    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ledger")
def get_ledger(user: dict = Depends(get_current_user)):
    return {"status": "success", "data": list_audit_ledger(user.get("role", "Admin"))}


@router.get("/certificate/{job_id}")
def download_certificate(job_id: str, user: dict = Depends(get_current_user)):
    if user.get("role") not in ["Admin", "ErasureOperator"]:
        raise HTTPException(status_code=403, detail="Insufficient privileges to download certificates.")

    job_data = get_job(job_id)
    if not job_data:
        raise HTTPException(status_code=404, detail="Job not found in immutable ledger.")
    if job_data.get("operation") != "SANITIZATION":
        raise HTTPException(status_code=403, detail="Certificates are only available for sanitization jobs.")

    cert_bytes = generate_nist_certificate(job_data)
    return Response(
        content=cert_bytes,
        media_type="text/html",
        headers={
            "Content-Disposition": f"inline; filename=NIST_SP800-88_Certificate_{job_id}.html"
        },
    )







































































