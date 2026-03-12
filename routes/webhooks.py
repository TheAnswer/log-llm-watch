"""Webhook ingestion endpoints and health check."""
import asyncio
from functools import partial

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from extraction import extract_dozzle_event, extract_syslog_event, extract_windows_event
from ingestion import ingest_event, _THREAD_POOL

router = APIRouter()


@router.get("/healthz")
def healthz():
    return {"ok": True}


@router.post("/dozzle")
async def dozzle_webhook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Expected JSON body")
    event = extract_dozzle_event(payload)
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(_THREAD_POOL, partial(ingest_event, payload, event))
    return JSONResponse(result)


@router.post("/windows")
async def windows_webhook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Expected JSON body")
    event = extract_windows_event(payload)
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(_THREAD_POOL, partial(ingest_event, payload, event))
    return JSONResponse(result)


@router.post("/syslog")
async def syslog_webhook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Expected JSON body")
    event = extract_syslog_event(payload)
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(_THREAD_POOL, partial(ingest_event, payload, event))
    return JSONResponse(result, headers={"Connection": "close"})
