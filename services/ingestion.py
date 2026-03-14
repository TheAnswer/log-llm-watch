"""Event ingestion: store, backfill, and ingest helper."""
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from core import config
from core.config import utcnow
from core.database import db
from services.incidents import attach_or_create_incident
from core.normalize import enrich_event
from services.suppression import log_ignored, should_ignore

_THREAD_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="db")
_INCIDENT_LOCK = threading.Lock()

_EVENT_COUNTS: dict[str, int] = {
    "total_received": 0,
    "total_stored": 0,
    "total_ignored": 0,
}
_EVENT_COUNTS_LOCK = threading.Lock()


def store_event(payload: Any, event: dict[str, str]) -> str:
    enriched = enrich_event(event)
    with _INCIDENT_LOCK, db() as conn:
        incident_id = attach_or_create_incident(conn, enriched)
        conn.execute(
            """
            INSERT INTO events (
                created_at, processed, source, host, container, stream, level, message,
                raw_json, fingerprint, ts, host_type, service, app_stack, event_class,
                dependency, canonical_fingerprint, incident_id, severity_norm, message_template, labels
            )
            VALUES (?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utcnow().isoformat(),
                enriched["source"], enriched["host"], enriched["container"],
                enriched["stream"], enriched["level"], enriched["message"],
                json.dumps(payload, ensure_ascii=False), enriched["fingerprint"],
                enriched["ts"], enriched["host_type"], enriched["service"],
                enriched["app_stack"], enriched["event_class"], enriched["dependency"],
                enriched["canonical_fingerprint"], incident_id, enriched["severity_norm"],
                enriched["message_template"], enriched["labels"],
            ),
        )
        conn.commit()
    return enriched["fingerprint"]


def backfill_existing_events(limit: int = 500) -> int:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000;")
        rows = conn.execute(
            """
            SELECT * FROM events
            WHERE canonical_fingerprint IS NULL OR canonical_fingerprint = ''
               OR event_class IS NULL OR event_class = ''
               OR message_template IS NULL OR message_template = ''
            ORDER BY id ASC LIMIT ?
            """,
            (limit,),
        ).fetchall()

        if not rows:
            return 0

        updated = 0
        for row in rows:
            event = {
                "source": row["source"] or "", "host": row["host"] or "",
                "container": row["container"] or "", "stream": row["stream"] or "",
                "level": row["level"] or "", "message": row["message"] or "",
            }
            enriched = enrich_event(event)
            enriched["ts"] = row["ts"] or row["created_at"] or enriched["ts"]
            incident_id = attach_or_create_incident(conn, enriched)

            conn.execute(
                """
                UPDATE events
                SET ts = ?, host_type = ?, service = ?, app_stack = ?, event_class = ?,
                    dependency = ?, canonical_fingerprint = ?, incident_id = ?,
                    severity_norm = ?, message_template = ?, labels = ?, fingerprint = ?
                WHERE id = ?
                """,
                (
                    enriched["ts"], enriched["host_type"], enriched["service"],
                    enriched["app_stack"], enriched["event_class"], enriched["dependency"],
                    enriched["canonical_fingerprint"], incident_id, enriched["severity_norm"],
                    enriched["message_template"], enriched["labels"],
                    row["fingerprint"] or enriched["fingerprint"], row["id"],
                ),
            )
            updated += 1

        conn.commit()
        return updated


def ingest_event(payload: Any, event: dict[str, str]) -> dict[str, Any]:
    """Run all blocking work (ignore check, DB write) off the async event loop."""
    with _EVENT_COUNTS_LOCK:
        _EVENT_COUNTS["total_received"] += 1

    t0 = time.monotonic()
    if should_ignore(event["message"]):
        with _EVENT_COUNTS_LOCK:
            _EVENT_COUNTS["total_ignored"] += 1
        log_ignored(event["container"], event["host"], event["message"],
                    "regex/suppress", (time.monotonic() - t0) * 1000)
        return {"stored": False, "reason": "ignored"}

    fp = store_event(payload, event)
    with _EVENT_COUNTS_LOCK:
        _EVENT_COUNTS["total_stored"] += 1
    return {"stored": True, "source": event["source"], "container": event["container"], "fingerprint": fp}
