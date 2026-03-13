"""Tests for services.ingestion — event storage and ingestion pipeline."""
import re
import sqlite3
from unittest.mock import patch

from core import config
from services.ingestion import ingest_event, store_event


class TestStoreEvent:
    def test_stores_event(self, tmp_db):
        payload = {"raw": True}
        event = {
            "source": "dozzle-webhook", "host": "node1", "container": "app",
            "stream": "", "level": "error", "message": "connection refused to db",
        }
        fp = store_event(payload, event)
        assert isinstance(fp, str)
        assert len(fp) == 20

        with sqlite3.connect(tmp_db) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM events WHERE fingerprint = ?", (fp,)).fetchone()
        assert row is not None
        assert row["host"] == "node1"
        assert row["event_class"] == "connect_refused"
        assert row["severity_norm"] == "error"

    def test_creates_incident(self, tmp_db):
        payload = {}
        event = {
            "source": "syslog", "host": "router", "container": "sshd",
            "stream": "", "level": "error", "message": "connection refused",
        }
        store_event(payload, event)

        with sqlite3.connect(tmp_db) as conn:
            count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        assert count >= 1


class TestIngestEvent:
    def test_stores_normal_event(self, tmp_db):
        with patch.object(config, "_IGNORE_PATTERNS", []):
            from services.suppression import load_suppressed_fingerprints
            load_suppressed_fingerprints()
            result = ingest_event({}, {
                "source": "syslog", "host": "h", "container": "c",
                "stream": "", "level": "", "message": "real error happened",
            })
        assert result["stored"] is True
        assert "fingerprint" in result

    def test_ignores_matching_pattern(self, tmp_db):
        with patch.object(config, "_IGNORE_PATTERNS", [re.compile("healthcheck")]):
            result = ingest_event({}, {
                "source": "syslog", "host": "h", "container": "c",
                "stream": "", "level": "", "message": "GET /healthcheck 200",
            })
        assert result["stored"] is False
        assert result["reason"] == "ignored"
