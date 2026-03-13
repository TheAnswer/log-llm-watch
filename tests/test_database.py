"""Tests for core.database — schema init and db() context manager."""
import sqlite3

from core import config
from core.database import db, init_db


class TestInitDb:
    def test_tables_exist(self, tmp_db):
        with sqlite3.connect(tmp_db) as conn:
            tables = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
        expected = {
            "events", "incidents", "daily_runs", "weekly_runs",
            "housekeeping_runs", "analysis_runs", "ntfy_log",
            "llm_call_log", "suppress_rules", "llm_noise_fingerprints",
        }
        assert expected.issubset(tables)

    def test_events_columns(self, tmp_db):
        with sqlite3.connect(tmp_db) as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
        for col in ["id", "message", "fingerprint", "canonical_fingerprint",
                     "event_class", "severity_norm", "incident_id"]:
            assert col in cols

    def test_llm_call_log_columns(self, tmp_db):
        with sqlite3.connect(tmp_db) as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(llm_call_log)").fetchall()}
        for col in ["prompt_tokens", "completion_tokens", "model", "caller", "response_preview"]:
            assert col in cols

    def test_suppress_rules_columns(self, tmp_db):
        with sqlite3.connect(tmp_db) as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(suppress_rules)").fetchall()}
        for col in ["match_type", "match_pattern", "hit_count", "last_hit_at"]:
            assert col in cols

    def test_idempotent(self, tmp_db):
        # Calling init_db again should not raise
        init_db()


class TestDbContextManager:
    def test_returns_connection(self, tmp_db):
        with db() as conn:
            assert isinstance(conn, sqlite3.Connection)
            conn.execute("SELECT 1").fetchone()

    def test_connection_closed_after(self, tmp_db):
        conn_ref = None
        with db() as conn:
            conn_ref = conn
        # After exiting, further operations should fail
        try:
            conn_ref.execute("SELECT 1")
            closed = False
        except Exception:
            closed = True
        assert closed
