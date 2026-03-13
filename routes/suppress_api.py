"""Suppress-rules CRUD endpoints."""
import sqlite3

from fastapi import APIRouter, HTTPException

from core import config
from services.suppression import load_suppressed_fingerprints, _SUPPRESS_HITS, _SUPPRESS_LOCK

router = APIRouter()


@router.get("/api/suppress-rules")
def api_list_suppress_rules():
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, match_type, canonical_fingerprint, match_host, match_pattern,
                   incident_title, event_class, reason, created_at, hit_count, last_hit_at
            FROM suppress_rules ORDER BY created_at DESC
            """
        ).fetchall()
    items = []
    with _SUPPRESS_LOCK:
        pending = dict(_SUPPRESS_HITS)
    for row in rows:
        d = dict(row)
        d["hit_count"] = (d.get("hit_count") or 0) + pending.get(d["id"], 0)
        items.append(d)
    return {"items": items}


@router.delete("/api/suppress-rules/{rule_id}")
def api_delete_suppress_rule(rule_id: int):
    with sqlite3.connect(config.DB_PATH) as conn:
        result = conn.execute("DELETE FROM suppress_rules WHERE id = ?", (rule_id,))
        conn.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Rule not found")
    load_suppressed_fingerprints()
    return {"ok": True, "rule_id": rule_id}
