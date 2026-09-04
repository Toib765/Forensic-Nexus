from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
from core.database import authenticate_user, get_session, revoke_session

router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
@router.post("/login/")
def login(req: LoginRequest):
    auth_data = authenticate_user(req.username, req.password)
    if not auth_data:
        raise HTTPException(status_code=401, detail="Invalid username or password. Access denied.")
    return {"status": "success", "data": auth_data}

@router.get("/me")
@router.get("/me/")
def me(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authentication token.")
    token = authorization.split(" ")[1]
    user = get_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid.")
    return {"status": "success", "data": user}

@router.post("/logout")
@router.post("/logout/")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        revoke_session(token)
    return {"status": "success", "message": "Session terminated."}
