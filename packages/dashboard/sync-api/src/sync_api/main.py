"""
sync_api — STUB (M3)
Full implementation in Milestone M3.
"""
from fastapi import FastAPI

app = FastAPI(title="censprobe-sync-api", version="0.1.0-stub")

@app.get("/health")
async def health():
    return {"status": "ok", "note": "stub — M3 not implemented yet"}

@app.post("/refresh")
async def refresh():
    return {"status": "stub", "new_reports": 0, "note": "Full implementation in M3"}
