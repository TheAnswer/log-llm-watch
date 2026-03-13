"""Incident CRUD, analysis, digest, and suppress endpoints."""
import re
import sqlite3
import threading
import time
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from core import config
from core.config import safe_json_loads, utcnow
from services.incidents import (
    analyze_incident_with_ollama,
    analyze_missing_incidents,
    build_incident_context,
    build_incident_context_filtered,
    build_incident_llm_context,
    generate_open_incidents_digest,
)
from services.suppression import load_suppressed_fingerprints

router = APIRouter()

_DIGEST_CACHE: dict[str, Any] = {}
_DIGEST_CACHE_TTL_SECS = 300
_DIGEST_CACHE_LOCK = threading.Lock()


def _incident_row_to_dict(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "status": row["status"],
        "severity": row["severity"],
        "title": row["title"],
        "event_class": row["event_class"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "event_count": row["event_count"],
        "affected_nodes": safe_json_loads(row["affected_nodes"], []),
        "affected_services": safe_json_loads(row["affected_services"], []),
        "root_cause_candidates": safe_json_loads(row["root_cause_candidates"], []),
        "summary": row["summary"] or "",
        "probable_root_cause": row["probable_root_cause"] or "",
        "confidence": row["confidence"] or "",
        "last_analyzed_at": row["last_analyzed_at"] or "",
        "analysis_json": safe_json_loads(row["analysis_json"], None),
        "metadata": safe_json_loads(row["metadata"], {}),
    }


@router.get("/api/incidents")
def api_incidents(status: str = "open", limit: int = 20, severity: str = "", offset: int = 0):
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    conditions: list[str] = []
    params: list[Any] = []
    if status != "all":
        conditions.append("status = ?")
        params.append(status)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(f"SELECT COUNT(*) FROM incidents {where_clause}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM incidents {where_clause} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return {"items": [_incident_row_to_dict(r) for r in rows], "total": total, "offset": offset, "limit": limit}


@router.patch("/api/incidents/{incident_id}")
def api_update_incident(incident_id: int, status: str):
    allowed = {"open", "closed"}
    if status not in allowed:
        raise HTTPException(status_code=400, detail=f"status must be one of {allowed}")
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        incident = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        conn.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
                     (status, utcnow().isoformat(), incident_id))
        conn.commit()
    return {"ok": True, "incident_id": incident_id, "status": status}


@router.get("/api/incidents/open/llm-digest")
def api_open_incidents_llm_digest(limit: int = 10, include_raw_response: bool = False, refresh: bool = False):
    with _DIGEST_CACHE_LOCK:
        cached = _DIGEST_CACHE.get("result")
        cached_at = _DIGEST_CACHE.get("cached_at", 0.0)
        age = time.monotonic() - cached_at
        if cached is not None and not refresh and age < _DIGEST_CACHE_TTL_SECS:
            return cached
    try:
        result = generate_open_incidents_digest(limit=limit, include_raw_response=include_raw_response)
        with _DIGEST_CACHE_LOCK:
            _DIGEST_CACHE["result"] = result
            _DIGEST_CACHE["cached_at"] = time.monotonic()
        return result
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


@router.get("/api/incidents/{incident_id}")
def api_incident_detail(incident_id: int, event_limit: int = 50):
    event_limit = max(1, min(event_limit, 200))
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        incident = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        events = conn.execute(
            """
            SELECT id, ts, created_at, source, host, container, stream, level, severity_norm,
                   event_class, dependency, message, message_template, canonical_fingerprint
            FROM events WHERE incident_id = ? ORDER BY ts ASC, id ASC LIMIT ?
            """,
            (incident_id, event_limit),
        ).fetchall()
    inc = _incident_row_to_dict(incident)
    inc["primary_fingerprint"] = incident["primary_fingerprint"]
    return {"incident": inc, "events": [dict(row) for row in events]}


@router.get("/api/incidents/{incident_id}/context")
def api_incident_context(incident_id: int, event_limit: int = 20, nearby_limit: int = 100,
                         similar_limit: int = 5, minutes_before: int = 2, minutes_after: int = 10):
    return build_incident_context(incident_id=incident_id, event_limit=event_limit,
                                  nearby_limit=nearby_limit, similar_limit=similar_limit,
                                  minutes_before=minutes_before, minutes_after=minutes_after)


@router.get("/api/incidents/{incident_id}/context-filtered")
def api_incident_context_filtered(incident_id: int, event_limit: int = 20, nearby_limit: int = 100,
                                  similar_limit: int = 5, minutes_before: int = 2, minutes_after: int = 10,
                                  exclude_info: bool = True, exclude_unknown: bool = True,
                                  exclude_noise: bool = True, exclude_same_incident_from_nearby: bool = False):
    return build_incident_context_filtered(
        incident_id=incident_id, event_limit=event_limit, nearby_limit=nearby_limit,
        similar_limit=similar_limit, minutes_before=minutes_before, minutes_after=minutes_after,
        exclude_info=exclude_info, exclude_unknown=exclude_unknown, exclude_noise=exclude_noise,
        exclude_same_incident_from_nearby=exclude_same_incident_from_nearby)


@router.get("/api/incidents/{incident_id}/llm-context")
def api_incident_llm_context(incident_id: int, event_limit: int = 12, nearby_limit: int = 60,
                             similar_limit: int = 5, minutes_before: int = 2, minutes_after: int = 10):
    return build_incident_llm_context(incident_id=incident_id, event_limit=event_limit,
                                      nearby_limit=nearby_limit, similar_limit=similar_limit,
                                      minutes_before=minutes_before, minutes_after=minutes_after)


@router.post("/api/incidents/{incident_id}/analyze")
def api_analyze_incident(incident_id: int, persist_summary: bool = True, include_raw_response: bool = False):
    try:
        return analyze_incident_with_ollama(incident_id=incident_id, persist_summary=persist_summary,
                                           include_raw_response=include_raw_response)
    except HTTPException:
        raise
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "incident_id": incident_id, "error": str(e)})


@router.post("/api/incidents/analyze-missing")
def api_analyze_missing_incidents(limit: int = 10, include_closed: bool = False, skip_info_unknown: bool = True):
    try:
        return analyze_missing_incidents(limit=limit, include_closed=include_closed,
                                         skip_info_unknown=skip_info_unknown)
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


@router.post("/api/incidents/{incident_id}/suppress")
def api_suppress_incident(incident_id: int, scope: str = "fingerprint", reason: str = "",
                          match_host: str = "", match_pattern: str = ""):
    allowed_scopes = {"fingerprint", "event_class", "event_class_host", "message_regex"}
    if scope not in allowed_scopes:
        raise HTTPException(status_code=400, detail=f"scope must be one of {allowed_scopes}")

    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        incident = conn.execute(
            "SELECT id, primary_fingerprint, title, event_class FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        fingerprint = incident["primary_fingerprint"] or ""
        event_class = incident["event_class"] or ""

        if scope == "fingerprint" and not fingerprint:
            raise HTTPException(status_code=400, detail="Incident has no canonical fingerprint")
        if scope in ("event_class", "event_class_host") and not event_class:
            raise HTTPException(status_code=400, detail="Incident has no event_class")
        if scope == "event_class_host" and not match_host:
            raise HTTPException(status_code=400, detail="match_host is required for event_class_host scope")
        if scope == "message_regex":
            if not match_pattern:
                raise HTTPException(status_code=400, detail="match_pattern is required for message_regex scope")
            try:
                re.compile(match_pattern)
            except re.error as e:
                raise HTTPException(status_code=400, detail=f"Invalid regex: {e}")

        host_val = match_host if scope == "event_class_host" else ""
        pattern_val = match_pattern if scope == "message_regex" else ""

        try:
            conn.execute(
                """
                INSERT INTO suppress_rules
                    (match_type, canonical_fingerprint, match_host, match_pattern,
                     incident_title, event_class, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scope, fingerprint, host_val, pattern_val,
                 incident["title"], event_class, reason, utcnow().isoformat()),
            )
        except sqlite3.IntegrityError:
            pass

        conn.execute("UPDATE incidents SET status = 'closed', updated_at = ? WHERE id = ?",
                     (utcnow().isoformat(), incident_id))
        conn.commit()

    load_suppressed_fingerprints()
    return {"ok": True, "incident_id": incident_id, "scope": scope}
