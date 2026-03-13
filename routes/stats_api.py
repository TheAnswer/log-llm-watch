"""LLM stats and ntfy log endpoints."""
import sqlite3
from datetime import timedelta

from fastapi import APIRouter

import config
from config import utcnow
from ollama import _LLM_STATS

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
