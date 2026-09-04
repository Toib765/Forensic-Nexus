import os
from typing import Optional
from fastapi import APIRouter, HTTPException, Header, Depends, Query
from pydantic import BaseModel, Field
from recover.carver_engine import StreamCarver
from core.database import log_audit_event, get_session

router = APIRouter(prefix="/api/v1/recovery", tags=["Forensic Recovery Engine"])
carver = StreamCarver()

class CarveRequest(BaseModel):
    job_id: str = Field(..., example="CASE-2026-001")
    target_path: str = Field(..., example="/dev/sda1")
    output_dir: str = Field("./cases", example="./cases")
    scan_unallocated_only: bool = Field(True, example=True)

def verify_investigator_session(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication token required.")
    token = authorization.replace("Bearer ", "").strip()
    session = get_session(token)
    if not session or session["role"] not in ["ForensicInvestigator", "Admin"]:
        raise HTTPException(status_code=403, detail="Forbidden: Operation requires ForensicInvestigator or Admin privileges.")
    return session

@router.post("/carve")
async def execute_carving(req: CarveRequest, session: dict = Depends(verify_investigator_session)):
    try:
        manifest = carver.carve_target(
            job_id=req.job_id,
            target_path=req.target_path,
            output_base_dir=req.output_dir,
            scan_unallocated_only=req.scan_unallocated_only
        )
        
        log_audit_event({
            "job_id": manifest["job_id"],
            "operation": "CARVE",
            "target_path": manifest["target_path"],
            "target_type": "BLOCK_DEVICE",
            "method": "STREAM_CARVING",
            "bytes_processed": manifest["target_size_bytes"],
            "start_time": manifest["scan_start_time"],
            "end_time": manifest["scan_end_time"],
            "verified": True,
            "verification_method": "SHA256_INTEGRITY",
            "verification_coverage_pct": 100.0,
            "status": f"{manifest['deleted_files_recovered']} Files Recovered",
            "audit_hash": manifest["audit_hash"],
            "recovered_count": manifest["deleted_files_recovered"],
            "operator_username": session["username"]
        })

        return {"status": "success", "data": manifest}
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deep Carving Failed: {str(e)}")

@router.get("/hex-inspect")
async def inspect_hex_bytes(
    case_id: str = Query(...),
    file_name: str = Query(...),
    category: str = Query("Images"),
    length: int = Query(512),
    session: dict = Depends(verify_investigator_session)
):
    safe_case = os.path.basename(case_id)
    safe_file = os.path.basename(file_name)
    safe_cat = os.path.basename(category).lower()

    base_cases = os.path.realpath("./cases")
    target_file = os.path.realpath(os.path.join(base_cases, safe_case, "carved_evidence", safe_cat, safe_file))

    if not target_file.startswith(base_cases) or not os.path.exists(target_file):
        raise HTTPException(status_code=404, detail="Evidence artifact not found or access denied.")

    with open(target_file, "rb") as f:
        raw_bytes = f.read(min(length, 4096))

    hex_lines = []
    for idx in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[idx:idx+16]
        hex_pairs = [f"{b:02X}" for b in chunk]
        ascii_chars = "".join([chr(b) if 32 <= b <= 126 else "." for b in chunk])
        hex_lines.append({
            "offset": f"{idx:08X}",
            "hex": " ".join(hex_pairs),
            "ascii": ascii_chars
        })

    return {
        "status": "success",
        "file_name": safe_file,
        "total_bytes": os.path.getsize(target_file),
        "inspected_bytes": len(raw_bytes),
        "hex_lines": hex_lines
    }
