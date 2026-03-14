#!/usr/bin/env python3
"""Homelab LLM Watch — FastAPI application entry point."""
import threading
import time

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from services.background import _check_ollama_health, _run_backfill, analysis_loop
from core.database import init_db
from services.suppression import load_suppressed_fingerprints

from routes.webhooks import router as webhooks_router
from routes.incidents_api import router as incidents_router
from routes.events_api import router as events_router
from routes.admin import router as admin_router
from routes.tools import router as tools_router
from routes.suppress_api import router as suppress_router
from routes.stats_api import router as stats_router
from routes.chat_api import router as chat_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    load_suppressed_fingerprints()
    _check_ollama_health()
    threading.Thread(target=_run_backfill, daemon=True).start()
    threading.Thread(target=analysis_loop, daemon=True).start()
    yield


app = FastAPI(title="Homelab LLM Watch", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    t0 = time.monotonic()
    response = await call_next(request)
    elapsed_ms = (time.monotonic() - t0) * 1000
    print(
        f"[http] {request.method} {request.url.path} -> {response.status_code} ({elapsed_ms:.1f}ms)",
        flush=True,
    )
    return response


app.include_router(webhooks_router)
app.include_router(incidents_router)
app.include_router(events_router)
app.include_router(admin_router)
app.include_router(tools_router)
app.include_router(suppress_router)
app.include_router(stats_router)
app.include_router(chat_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8088)
