from fastapi import FastAPI
from eraser_router import router as eraser_router

app = FastAPI(title="Forensic Nexus - Erasure API")
app.include_router(eraser_router)
