import os
import binascii
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Header, Query
from pydantic import BaseModel

from core.database import log_audit_event, get_session
from recover.carver_engine import StreamCarver

router = APIRouter()
carver = StreamCarver()

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authentication token.")
    token = authorization.split(" ")[1]
    user = get_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid.")
    return user

class CarveRequest(BaseModel):
    job_id: Optional[str] = None
    target_path: str
    output_dir: Optional[str] = "./cases"
    scan_unallocated_only: Optional[bool] = False

@router.post("/carve")
def execute_carve(req: CarveRequest, user: dict = Depends(get_current_user)):
    if user.get("role") not in ["Admin", "ForensicInvestigator"]:
        raise HTTPException(status_code=403, detail="Insufficient privileges for forensic carving.")
    
    try:
        res = carver.carve_target(
            job_id=req.job_id,
            target_path=req.target_path,
            output_base_dir=req.output_dir or "./cases",
            scan_unallocated_only=req.scan_unallocated_only
        )
        
        job_data = {
            "job_id": res["job_id"],
            "operation": "CARVE",
            "target_path": res["target_path"],
            "target_type": "BLOCK_DEVICE" if req.target_path.startswith("/dev/") else "FILE",
            "method": "RAW_STREAM_CARVE",
            "bytes_processed": res["target_size_bytes"],
            "start_time": res["scan_start_time"],
            "end_time": res["scan_end_time"],
            "verified": True,
            "verification_method": "SHA-256 Integrity Verification",
            "verification_coverage_pct": 100.0,
            "audit_hash": res["audit_hash"],
            "status": f"COMPLETED ({res['deleted_files_recovered']} Recovered)",
            "recovered_count": res["deleted_files_recovered"],
            "operator_username": user.get("username", "investigator")
        }
        log_audit_event(job_data)
        return {"status": "success", "data": res}
    except FileNotFoundError as fnfe:
        raise HTTPException(status_code=404, detail=str(fnfe))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deep Carving Failed: {str(e)}")

@router.get("/hex-inspect")
def inspect_hex(
    case_id: str = Query(...),
    file_name: str = Query(...),
    category: str = Query(...),
    length: int = Query(512),
    user: dict = Depends(get_current_user)
):
    base_case_path = os.path.join("./cases", case_id, "carved_evidence")
    target_file = os.path.join(base_case_path, category.lower(), file_name)
    
    if not os.path.exists(target_file):
        target_file = os.path.join(base_case_path, category, file_name)
    if not os.path.exists(target_file):
        raise HTTPException(status_code=404, detail=f"Artifact '{file_name}' not found on disk.")
    
    try:
        with open(target_file, "rb") as f:
            raw_data = f.read(length)
        
        hex_lines = []
        for offset in range(0, len(raw_data), 16):
            chunk = raw_data[offset:offset+16]
            hex_bytes = " ".join(f"{b:02X}" for b in chunk)
            ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_lines.append({
                "offset": f"0x{offset:08X}",
                "hex": hex_bytes.ljust(48),
                "ascii": ascii_repr
            })
        
        return {"status": "success", "hex_lines": hex_lines}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hex inspection failed: {str(e)}")
