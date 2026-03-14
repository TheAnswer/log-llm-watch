"""Database initialization and connection helpers."""
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from core import config


def init_db() -> None:
    Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")

        def column_exists(table: str, column: str) -> bool:
            rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
            return any(row[1] == column for row in rows)

        def add_column_if_missing(table: str, column: str, col_type_sql: str) -> None:
            if not column_exists(table, column):
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type_sql}")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                processed INTEGER NOT NULL DEFAULT 0,
                source TEXT,
                host TEXT,
                container TEXT,
                stream TEXT,
                level TEXT,
                message TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                fingerprint TEXT NOT NULL
            )
            """
        )

        add_column_if_missing("events", "ts", "TEXT")
        add_column_if_missing("events", "host_type", "TEXT")
        add_column_if_missing("events", "service", "TEXT")
        add_column_if_missing("events", "app_stack", "TEXT")
        add_column_if_missing("events", "event_class", "TEXT")
        add_column_if_missing("events", "dependency", "TEXT")
        add_column_if_missing("events", "canonical_fingerprint", "TEXT")
        add_column_if_missing("events", "incident_id", "INTEGER")
        add_column_if_missing("events", "noise_score", "REAL DEFAULT 0")
        add_column_if_missing("events", "severity_norm", "TEXT")
        add_column_if_missing("events", "message_template", "TEXT")
        add_column_if_missing("events", "labels", "TEXT DEFAULT '{}'")
        add_column_if_missing("events", "suppressed", "INTEGER NOT NULL DEFAULT 0")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL DEFAULT 'open',
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                event_class TEXT,
                primary_fingerprint TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0,
                affected_nodes TEXT NOT NULL DEFAULT '[]',
                affected_services TEXT NOT NULL DEFAULT '[]',
                root_cause_candidates TEXT NOT NULL DEFAULT '[]',
                summary TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        add_column_if_missing("incidents", "analysis_json", "TEXT")
        add_column_if_missing("incidents", "probable_root_cause", "TEXT")
        add_column_if_missing("incidents", "confidence", "TEXT")
        add_column_if_missing("incidents", "last_analyzed_at", "TEXT")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_processed_created ON events(processed, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_canonical_fp ON events(canonical_fingerprint)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_event_class_ts ON events(event_class, ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events(host, ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_container_ts ON events(container, ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_incident_id ON events(incident_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status_last_seen ON incidents(status, last_seen)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_primary_fp ON incidents(primary_fingerprint)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_event_class_last_seen ON incidents(event_class, last_seen)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS daily_runs (
                run_date TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS weekly_runs (
                run_key TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS housekeeping_runs (
                run_key TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                prompt TEXT NOT NULL,
                raw_response TEXT NOT NULL,
                parsed_json TEXT,
                overall_status TEXT,
                finding_count INTEGER NOT NULL DEFAULT 0,
                event_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analysis_runs_created_at ON analysis_runs(created_at)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ntfy_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sent_at TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                priority TEXT NOT NULL DEFAULT 'default',
                source TEXT NOT NULL DEFAULT '',
                message TEXT NOT NULL DEFAULT ''
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_call_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                called_at TEXT NOT NULL,
                duration_seconds REAL NOT NULL,
                error INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        add_column_if_missing("llm_call_log", "prompt_tokens", "INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing("llm_call_log", "completion_tokens", "INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing("llm_call_log", "model", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing("llm_call_log", "caller", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing("llm_call_log", "response_preview", "TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_call_log_called_at ON llm_call_log(called_at)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS suppress_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                match_type TEXT NOT NULL DEFAULT 'fingerprint',
                canonical_fingerprint TEXT NOT NULL DEFAULT '',
                match_host TEXT NOT NULL DEFAULT '',
                incident_title TEXT NOT NULL DEFAULT '',
                event_class TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        add_column_if_missing("suppress_rules", "match_type", "TEXT NOT NULL DEFAULT 'fingerprint'")
        add_column_if_missing("suppress_rules", "match_host", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing("suppress_rules", "match_pattern", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing("suppress_rules", "hit_count", "INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing("suppress_rules", "last_hit_at", "TEXT")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ignored_daily (
                day TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_noise_fingerprints (
                fingerprint TEXT PRIMARY KEY,
                suppressed_until TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


@contextmanager
def db():
    conn = sqlite3.connect(config.DB_PATH)
    try:
        conn.execute("PRAGMA busy_timeout=5000;")
        yield conn
    finally:
        conn.close()
