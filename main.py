import os
import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from core.database import init_db
from core.auth_router import router as auth_router
from recover.recovery_router import router as recovery_router
from eraser.eraser_router import router as erasure_router

init_db()

app = FastAPI(title="Forensic Nexus", version="1.0.0")

# API Routers (Mounted before static handlers)
app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(recovery_router, prefix="/api/v1/recovery", tags=["recovery"])
app.include_router(erasure_router, prefix="/api/v1/erasure", tags=["erasure"])
app.include_router(erasure_router, prefix="/api/v1/eraser", tags=["eraser_alias"])

# Storage & Evidence Static Handlers
base_dir = os.path.dirname(os.path.abspath(__file__))
cases_path = os.path.join(base_dir, "cases")
static_path = os.path.join(base_dir, "static")

os.makedirs(cases_path, exist_ok=True)
os.makedirs(static_path, exist_ok=True)

app.mount("/cases", StaticFiles(directory=cases_path), name="cases")

@app.get("/")
def read_root():
    return FileResponse(os.path.join(static_path, "index.html"))

@app.get("/style.css")
def read_css():
    return FileResponse(os.path.join(static_path, "style.css"))

@app.get("/app.js")
def read_js():
    return FileResponse(os.path.join(static_path, "app.js"))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
