"""Admin endpoints: config reload, backfill, reports, vacuum."""
from fastapi import APIRouter
from fastapi.responses import JSONResponse

import config
from housekeeping import vacuum_db
from ingestion import backfill_existing_events
from reports import send_daily_report, send_weekly_report

router = APIRouter()


@router.post("/admin/reload-config")
def admin_reload_config():
    config.reload()
    return {"ok": True, "message": "Config reloaded"}


@router.post("/admin/backfill-events")
def admin_backfill_events(limit: int = 1000):
    try:
        count = backfill_existing_events(limit=max(1, min(limit, 5000)))
        return {"ok": True, "updated": count}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


@router.post("/daily-report-now")
def daily_report_now():
    try:
        send_daily_report()
        return {"ok": True}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


@router.post("/weekly-report-now")
def weekly_report_now():
    try:
        send_weekly_report()
        return {"ok": True}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


@router.post("/vacuum-now")
def vacuum_now():
    try:
        vacuum_db()
        return {"ok": True}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
