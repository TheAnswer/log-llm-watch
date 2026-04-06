"""LLM stats and ntfy log endpoints."""
import sqlite3
from datetime import timedelta

from fastapi import APIRouter

from core import config
from core.config import utcnow
from services.ingestion import _EVENT_COUNTS
from services.ollama import _LLM_STATS

router = APIRouter()


@router.get("/api/llm-stats")
def api_llm_stats(days: int = 7):
    days = max(1, min(days, 90))
    cutoff = (utcnow() - timedelta(days=days)).isoformat()
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT COUNT(*) AS total_calls,
                   SUM(CASE WHEN error = 1 THEN 1 ELSE 0 END) AS total_errors,
                   COALESCE(SUM(duration_seconds), 0) AS total_seconds,
                   COALESCE(AVG(duration_seconds), 0) AS avg_seconds,
                   COALESCE(MIN(duration_seconds), 0) AS min_seconds,
                   COALESCE(MAX(duration_seconds), 0) AS max_seconds,
                   COALESCE(SUM(prompt_tokens), 0) AS total_prompt_tokens,
                   COALESCE(SUM(completion_tokens), 0) AS total_completion_tokens
            FROM llm_call_log WHERE called_at >= ?
            """,
            (cutoff,),
        ).fetchone()
        daily = conn.execute(
            """
            SELECT DATE(called_at) AS day,
                   COUNT(*) AS calls,
                   SUM(CASE WHEN error = 1 THEN 1 ELSE 0 END) AS errors,
                   ROUND(SUM(duration_seconds), 1) AS total_sec,
                   ROUND(AVG(duration_seconds), 1) AS avg_sec,
                   SUM(prompt_tokens) AS prompt_tokens,
                   SUM(completion_tokens) AS completion_tokens
            FROM llm_call_log WHERE called_at >= ?
            GROUP BY DATE(called_at) ORDER BY day
            """,
            (cutoff,),
        ).fetchall()
        recent = conn.execute(
            "SELECT called_at, duration_seconds, error, prompt_tokens, completion_tokens, model FROM llm_call_log ORDER BY id DESC LIMIT 20",
        ).fetchall()
    total_tokens = int(row["total_prompt_tokens"]) + int(row["total_completion_tokens"])
    return {
        "period_days": days,
        "total_calls": row["total_calls"],
        "total_errors": row["total_errors"],
        "total_seconds": round(row["total_seconds"], 1),
        "avg_seconds": round(row["avg_seconds"], 1),
        "min_seconds": round(row["min_seconds"], 1),
        "max_seconds": round(row["max_seconds"], 1),
        "total_prompt_tokens": int(row["total_prompt_tokens"]),
        "total_completion_tokens": int(row["total_completion_tokens"]),
        "total_tokens": total_tokens,
        "daily": [dict(d) for d in daily],
        "recent": [dict(r) for r in recent],
        "session": dict(_LLM_STATS),
    }


@router.get("/api/event-stats")
def api_event_stats(days: int = 7):
    days = max(1, min(days, 90))
    cutoff = (utcnow() - timedelta(days=days)).isoformat()
    with sqlite3.connect(config.DB_PATH) as conn:
        total_stored = conn.execute(
            "SELECT COUNT(*) FROM events WHERE created_at >= ?", (cutoff,)
        ).fetchone()[0]
        by_severity = conn.execute(
            """
            SELECT COALESCE(severity_norm, 'unknown') AS sev, COUNT(*) AS cnt
            FROM events WHERE created_at >= ?
            GROUP BY sev ORDER BY cnt DESC
            """,
            (cutoff,),
        ).fetchall()
        by_source = conn.execute(
            """
            SELECT COALESCE(source, 'unknown') AS src, COUNT(*) AS cnt
            FROM events WHERE created_at >= ?
            GROUP BY src ORDER BY cnt DESC
            """,
            (cutoff,),
        ).fetchall()
        by_event_class = conn.execute(
            """
            SELECT COALESCE(event_class, 'unknown') AS ec, COUNT(*) AS cnt
            FROM events WHERE created_at >= ?
            GROUP BY ec ORDER BY cnt DESC LIMIT 20
            """,
            (cutoff,),
        ).fetchall()
        daily = conn.execute(
            """
            SELECT DATE(created_at) AS day, COUNT(*) AS cnt
            FROM events WHERE created_at >= ?
            GROUP BY DATE(created_at) ORDER BY day
            """,
            (cutoff,),
        ).fetchall()
        open_incidents = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'open'"
        ).fetchone()[0]
        suppress_rules = conn.execute(
            "SELECT COUNT(*) FROM suppress_rules"
        ).fetchone()[0]
        cutoff_day = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
        total_ignored = conn.execute(
            "SELECT COALESCE(SUM(count), 0) FROM ignored_daily WHERE day >= ?",
            (cutoff_day,),
        ).fetchone()[0]
    return {
        "period_days": days,
        "total_stored": total_stored,
        "total_ignored": total_ignored,
        "open_incidents": open_incidents,
        "active_suppress_rules": suppress_rules,
        "by_severity": {r[0]: r[1] for r in by_severity},
        "by_source": {r[0]: r[1] for r in by_source},
        "by_event_class": {r[0]: r[1] for r in by_event_class},
        "daily": [{"day": r[0], "count": r[1]} for r in daily],
        "session": dict(_EVENT_COUNTS),
    }


@router.get("/api/llm-log")
def api_llm_log(limit: int = 50):
    limit = max(1, min(limit, 200))
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, called_at, duration_seconds, error, prompt_tokens, completion_tokens,
                   model, caller, response_preview
            FROM llm_call_log ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return {"items": [dict(r) for r in rows]}


@router.get("/api/ntfy-log")
def api_ntfy_log(limit: int = 50):
    limit = max(1, min(limit, 200))
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, sent_at, title, priority, source, message FROM ntfy_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return {"items": [dict(row) for row in rows]}


@router.get("/api/reports/daily")
def api_daily_reports(limit: int = 50):
    limit = max(1, min(limit, 200))
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, sent_at, title, priority, source, message FROM ntfy_log WHERE source = 'daily_report' ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return {"items": [dict(row) for row in rows]}


@router.get("/api/reports/weekly")
def api_weekly_reports(limit: int = 50):
    limit = max(1, min(limit, 200))
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, sent_at, title, priority, source, message FROM ntfy_log WHERE source = 'weekly_report' ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return {"items": [dict(row) for row in rows]}
