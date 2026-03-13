"""Tests for services.incidents — incident lifecycle."""
import sqlite3

from core import config
from core.config import utcnow
from core.normalize import enrich_event
from services.incidents import (
    attach_or_create_incident,
    close_stale_incidents,
    incident_title_for_event,
    root_cause_candidates_for_event,
)


class TestIncidentTitleForEvent:
    def test_known_class(self):
        title = incident_title_for_event({"event_class": "dns_failure", "service": "coredns"})
        assert "DNS" in title
        assert "coredns" in title

    def test_unknown_class(self):
        title = incident_title_for_event({"event_class": "unknown"})
        assert "Unclassified" in title

    def test_no_service(self):
        title = incident_title_for_event({"event_class": "oom_kill"})
        assert "memory" in title.lower()


class TestRootCauseCandidates:
    def test_known_class(self):
        candidates = root_cause_candidates_for_event({"event_class": "dns_failure"})
        assert len(candidates) >= 1

    def test_unknown_class(self):
        candidates = root_cause_candidates_for_event({"event_class": "unknown"})
        assert candidates == []


class TestAttachOrCreateIncident:
    def _make_enriched(self, message="connection refused"):
        return enrich_event({
            "source": "syslog", "host": "node1", "container": "app",
            "stream": "", "level": "error", "message": message,
        })

    def test_creates_new_incident(self, tmp_db):
        enriched = self._make_enriched()
        with sqlite3.connect(tmp_db) as conn:
            incident_id = attach_or_create_incident(conn, enriched)
            conn.commit()
        assert incident_id is not None
        assert incident_id > 0

    def test_attaches_to_existing(self, tmp_db):
        enriched = self._make_enriched()
        with sqlite3.connect(tmp_db) as conn:
            id1 = attach_or_create_incident(conn, enriched)
            conn.commit()
            id2 = attach_or_create_incident(conn, enriched)
            conn.commit()
        assert id1 == id2

        with sqlite3.connect(tmp_db) as conn:
            count = conn.execute(
                "SELECT event_count FROM incidents WHERE id = ?", (id1,)
            ).fetchone()[0]
        assert count == 2

    def test_different_fingerprints_different_incidents(self, tmp_db):
        e1 = self._make_enriched("connection refused")
        e2 = self._make_enriched("database is locked")
        with sqlite3.connect(tmp_db) as conn:
            id1 = attach_or_create_incident(conn, e1)
            conn.commit()
            id2 = attach_or_create_incident(conn, e2)
            conn.commit()
        assert id1 != id2


class TestCloseStaleIncidents:
    def test_closes_old_open_incident(self, tmp_db):
        from datetime import timedelta
        old_time = (utcnow() - timedelta(hours=2)).isoformat()
        now = utcnow().isoformat()
        with sqlite3.connect(tmp_db) as conn:
            conn.execute(
                """INSERT INTO incidents (status, severity, title, event_class,
                   primary_fingerprint, first_seen, last_seen, event_count,
                   created_at, updated_at)
                   VALUES ('open', 'error', 'test', 'unknown', 'fp1',
                   ?, ?, 1, ?, ?)""",
                (old_time, old_time, now, now),
            )
            conn.commit()

        close_stale_incidents()

        with sqlite3.connect(tmp_db) as conn:
            status = conn.execute("SELECT status FROM incidents WHERE id = 1").fetchone()[0]
        assert status == "closed"
