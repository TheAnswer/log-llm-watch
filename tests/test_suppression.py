"""Tests for services.suppression — rule loading, matching, regex generation."""
import sqlite3
from unittest.mock import patch

from core import config
from services.suppression import (
    _SUPPRESS_FP,
    _SUPPRESS_REGEX,
    flush_suppress_hits,
    load_suppressed_fingerprints,
    should_ignore,
    template_to_suppress_pattern,
    _validate_suppress_regex,
)


class TestLoadSuppressedFingerprints:
    def test_loads_fingerprint_rules(self, tmp_db):
        with sqlite3.connect(tmp_db) as conn:
            conn.execute(
                "INSERT INTO suppress_rules (match_type, canonical_fingerprint, reason, created_at)"
                " VALUES ('fingerprint', 'abc123', 'test', '2026-01-01')"
            )
            conn.commit()
        load_suppressed_fingerprints()
        assert "abc123" in _SUPPRESS_FP

    def test_loads_regex_rules(self, tmp_db):
        with sqlite3.connect(tmp_db) as conn:
            conn.execute(
                "INSERT INTO suppress_rules (match_type, match_pattern, reason, created_at)"
                " VALUES ('message_regex', '(?i)test pattern \\S+', 'test', '2026-01-01')"
            )
            conn.commit()
        load_suppressed_fingerprints()
        assert len(_SUPPRESS_REGEX) >= 1

    def test_invalid_regex_skipped(self, tmp_db):
        with sqlite3.connect(tmp_db) as conn:
            conn.execute(
                "INSERT INTO suppress_rules (match_type, match_pattern, reason, created_at)"
                " VALUES ('message_regex', '[invalid', 'test', '2026-01-01')"
            )
            conn.commit()
        # Should not raise
        load_suppressed_fingerprints()


class TestShouldIgnore:
    def test_matches_ignore_pattern(self, tmp_db):
        import re
        with patch.object(config, "_IGNORE_PATTERNS", [re.compile("healthcheck")]):
            assert should_ignore("GET /healthcheck 200 OK")

    def test_no_match(self, tmp_db):
        import re
        with patch.object(config, "_IGNORE_PATTERNS", []):
            load_suppressed_fingerprints()  # clear regex cache
            assert not should_ignore("real error happened")

    def test_matches_suppress_regex(self, tmp_db):
        import re
        with patch.object(config, "_IGNORE_PATTERNS", []):
            with sqlite3.connect(tmp_db) as conn:
                conn.execute(
                    "INSERT INTO suppress_rules (match_type, match_pattern, reason, created_at)"
                    " VALUES ('message_regex', '(?i)noisy pattern', 'test', '2026-01-01')"
                )
                conn.commit()
            load_suppressed_fingerprints()
            assert should_ignore("this is a noisy pattern here")


class TestFlushSuppressHits:
    def test_flushes_to_db(self, tmp_db):
        with sqlite3.connect(tmp_db) as conn:
            conn.execute(
                "INSERT INTO suppress_rules (id, match_type, match_pattern, reason, created_at, hit_count)"
                " VALUES (1, 'message_regex', '(?i)test', 'test', '2026-01-01', 0)"
            )
            conn.commit()

        from services.suppression import _SUPPRESS_HITS, _SUPPRESS_LOCK
        with _SUPPRESS_LOCK:
            _SUPPRESS_HITS[1] = 5

        flush_suppress_hits()

        with sqlite3.connect(tmp_db) as conn:
            row = conn.execute("SELECT hit_count, last_hit_at FROM suppress_rules WHERE id = 1").fetchone()
        assert row[0] == 5
        assert row[1] is not None  # last_hit_at set


class TestTemplateTosuppressPattern:
    def test_basic_template(self):
        pattern = template_to_suppress_pattern("connection from <ip> port <num>")
        assert pattern.startswith("(?i)")
        import re
        compiled = re.compile(pattern)
        assert compiled.search("connection from 10.0.0.1 port 22")

    def test_json_wrapper_stripped(self):
        pattern = template_to_suppress_pattern(
            '{"message":"error in module <hex>","source":"x"}'
        )
        import re
        compiled = re.compile(pattern)
        assert compiled.search("error in module 0xDEAD")


class TestValidateSuppressRegex:
    def test_valid_pattern(self):
        assert _validate_suppress_regex("(?i)test \\S+", ["test foo", "test bar"])

    def test_invalid_regex(self):
        assert not _validate_suppress_regex("[invalid", ["test"])

    def test_non_matching(self):
        assert not _validate_suppress_regex("(?i)xyz", ["abc"])
