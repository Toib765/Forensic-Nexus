from eraser_router import router as eraser_router
from fastapi import FastAPI

app = FastAPI(title="Forensic Nexus - Erasure API")
app.include_router(eraser_router)
