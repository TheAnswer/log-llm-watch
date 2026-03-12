"""Event query and timeline endpoints."""
import sqlite3
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException

import config
from config import utcnow

router = APIRouter()


@router.get("/api/events")
def api_events(
    q: str = "",
    host: str = "",
    container: str = "",
    hours: int = 24,
    limit: int = 100,
    offset: int = 0,
):
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    cutoff = (utcnow() - timedelta(hours=max(1, hours))).isoformat()

    sql = """
    SELECT id, ts, created_at, source, host, container, stream, level, severity_norm,
           event_class, dependency, message, incident_id, processed, fingerprint
    FROM events
    WHERE created_at >= ?
    """
    params: list[Any] = [cutoff]

    if host:
        sql += " AND host = ?"
        params.append(host.lower())
    if container:
        sql += " AND container = ?"
        params.append(container)
    if q:
        sql += " AND (message LIKE ? OR message_template LIKE ? OR event_class LIKE ?)"
        like = f"%{q}%"
        params.extend([like, like, like])

    sql += " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()

    return {"items": [dict(row) for row in rows]}


@router.get("/api/timeline")
def api_timeline(ts: str, minutes_before: int = 2, minutes_after: int = 5, limit: int = 200):
    limit = max(1, min(limit, 500))
    try:
        center = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ts format")

    start = (center - timedelta(minutes=minutes_before)).isoformat()
    end = (center + timedelta(minutes=minutes_after)).isoformat()

    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, ts, created_at, source, host, container, stream, level, severity_norm,
                   event_class, dependency, message, incident_id
            FROM events WHERE ts >= ? AND ts <= ? ORDER BY ts ASC, id ASC LIMIT ?
            """,
            (start, end, limit),
        ).fetchall()

    return {"items": [dict(row) for row in rows]}
