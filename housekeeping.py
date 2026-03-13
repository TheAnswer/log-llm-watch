"""Data retention cleanup and vacuum."""
import sqlite3
from datetime import datetime, timedelta

import config
from config import utcnow


def cleanup_old_data() -> None:
    retention = config.CONFIG.get("retention", {})
    events_days = int(retention.get("events_days", 30))
    daily_runs_days = int(retention.get("daily_runs_days", 180))
    weekly_runs_days = int(retention.get("weekly_runs_days", 365))
    housekeeping_runs_days = int(retention.get("housekeeping_runs_days", 365))
    analysis_runs_days = int(retention.get("analysis_runs_days", 30))
    analysis_runs_cutoff = (utcnow() - timedelta(days=analysis_runs_days)).isoformat()

    events_cutoff = (utcnow() - timedelta(days=events_days)).isoformat()
    daily_cutoff = (utcnow() - timedelta(days=daily_runs_days)).isoformat()
    weekly_cutoff = (utcnow() - timedelta(days=weekly_runs_days)).isoformat()
    housekeeping_cutoff = (utcnow() - timedelta(days=housekeeping_runs_days)).isoformat()

    with sqlite3.connect(config.DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM events WHERE created_at < ?", (events_cutoff,))
        deleted_events = cur.rowcount
        cur.execute("DELETE FROM daily_runs WHERE created_at < ?", (daily_cutoff,))
        deleted_daily = cur.rowcount
        cur.execute("DELETE FROM weekly_runs WHERE created_at < ?", (weekly_cutoff,))
        deleted_weekly = cur.rowcount
        cur.execute("DELETE FROM housekeeping_runs WHERE created_at < ?", (housekeeping_cutoff,))
        deleted_housekeeping = cur.rowcount
        cur.execute("DELETE FROM analysis_runs WHERE created_at < ?", (analysis_runs_cutoff,))
        deleted_analysis_runs = cur.rowcount
        cur.execute("DELETE FROM llm_call_log WHERE called_at < ?", (analysis_runs_cutoff,))
        deleted_llm_calls = cur.rowcount
        conn.commit()

    print(
        "[cleanup] deleted "
        f"events={deleted_events} "
        f"daily_runs={deleted_daily} "
        f"weekly_runs={deleted_weekly} "
        f"housekeeping_runs={deleted_housekeeping} "
        f"analysis_runs={deleted_analysis_runs} "
        f"llm_calls={deleted_llm_calls}",
        flush=True,
    )


def vacuum_db() -> None:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute("VACUUM")
    print("[cleanup] vacuum completed", flush=True)


def housekeeping_run_key(prefix: str, now: datetime) -> str:
    return f"{prefix}-{now.strftime('%Y-%m-%d')}"


def housekeeping_already_ran(run_key: str) -> bool:
    with sqlite3.connect(config.DB_PATH) as conn:
        row = conn.execute("SELECT 1 FROM housekeeping_runs WHERE run_key = ?", (run_key,)).fetchone()
    return row is not None


def mark_housekeeping_ran(run_key: str) -> None:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO housekeeping_runs (run_key, created_at) VALUES (?, ?)",
            (run_key, utcnow().isoformat()),
        )
        conn.commit()


def cleanup_stale_suppress_rules(days: int = 30) -> int:
    """Remove auto-created suppress rules with no hits in the last N days."""
    from suppression import load_suppressed_fingerprints

    cutoff = (utcnow() - timedelta(days=days)).isoformat()
    with sqlite3.connect(config.DB_PATH) as conn:
        # Only prune auto-created rules (reason starts with "auto:")
        # that have never been hit, or whose last hit is older than cutoff
        cur = conn.execute(
            """
            DELETE FROM suppress_rules
            WHERE reason LIKE 'auto:%'
              AND (
                  (last_hit_at IS NULL AND created_at < ?)
                  OR (last_hit_at IS NOT NULL AND last_hit_at < ?)
              )
            """,
            (cutoff, cutoff),
        )
        deleted = cur.rowcount
        conn.commit()

    if deleted:
        load_suppressed_fingerprints()
        print(f"[cleanup] pruned {deleted} stale suppress rules (no hits in {days}d)", flush=True)
    return deleted


def maybe_run_cleanup() -> None:
    now = datetime.now()
    run_key = housekeeping_run_key("cleanup", now)
    if housekeeping_already_ran(run_key):
        return
    if now.hour >= 3:
        cleanup_old_data()
        suppress_days = int(config.CONFIG.get("retention", {}).get("suppress_rules_stale_days", 30))
        cleanup_stale_suppress_rules(days=suppress_days)
        mark_housekeeping_ran(run_key)
