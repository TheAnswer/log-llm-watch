"""Tests for services.housekeeping — cleanup and stale rule pruning."""
import sqlite3
from datetime import timedelta

from core import config
from core.config import utcnow
from services.housekeeping import cleanup_stale_suppress_rules


class TestCleanupStaleSuppressRules:
    def test_prunes_old_auto_rule_no_hits(self, tmp_db):
        old = (utcnow() - timedelta(days=60)).isoformat()
        with sqlite3.connect(tmp_db) as conn:
            conn.execute(
                "INSERT INTO suppress_rules (match_type, match_pattern, reason, created_at)"
                " VALUES ('message_regex', '(?i)test', 'auto: llm-ignore (template)', ?)",
                (old,),
            )
            conn.commit()

        deleted = cleanup_stale_suppress_rules(days=30)
        assert deleted == 1

        with sqlite3.connect(tmp_db) as conn:
            count = conn.execute("SELECT COUNT(*) FROM suppress_rules").fetchone()[0]
        assert count == 0

    def test_keeps_recent_auto_rule(self, tmp_db):
        recent = (utcnow() - timedelta(days=5)).isoformat()
        with sqlite3.connect(tmp_db) as conn:
            conn.execute(
                "INSERT INTO suppress_rules (match_type, match_pattern, reason, created_at)"
                " VALUES ('message_regex', '(?i)test', 'auto: llm-ignore (llm)', ?)",
                (recent,),
            )
            conn.commit()

        deleted = cleanup_stale_suppress_rules(days=30)
        assert deleted == 0

    def test_keeps_manual_rule(self, tmp_db):
        old = (utcnow() - timedelta(days=60)).isoformat()
        with sqlite3.connect(tmp_db) as conn:
            conn.execute(
                "INSERT INTO suppress_rules (match_type, match_pattern, reason, created_at)"
                " VALUES ('message_regex', '(?i)test', 'manual suppression', ?)",
                (old,),
            )
            conn.commit()

        deleted = cleanup_stale_suppress_rules(days=30)
        assert deleted == 0

    def test_keeps_rule_with_recent_hits(self, tmp_db):
        old_created = (utcnow() - timedelta(days=60)).isoformat()
        recent_hit = (utcnow() - timedelta(days=2)).isoformat()
        with sqlite3.connect(tmp_db) as conn:
            conn.execute(
                "INSERT INTO suppress_rules (match_type, match_pattern, reason, created_at, hit_count, last_hit_at)"
                " VALUES ('message_regex', '(?i)test', 'auto: llm-ignore (llm)', ?, 10, ?)",
                (old_created, recent_hit),
            )
            conn.commit()

        deleted = cleanup_stale_suppress_rules(days=30)
        assert deleted == 0
