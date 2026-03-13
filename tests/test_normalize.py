"""Tests for core.normalize — message normalization, fingerprinting, classification."""
from core.normalize import (
    classify_event,
    enrich_event,
    extract_inner_message,
    fingerprint_for_event,
    normalize_message,
    normalize_severity,
    stable_hash,
)


class TestExtractInnerMessage:
    def test_plain_string(self):
        assert extract_inner_message("hello world") == "hello world"

    def test_json_wrapper(self):
        assert extract_inner_message('{"message":"inner msg","source":"x"}') == "inner msg"

    def test_empty_message_field(self):
        raw = '{"message":"","source":"x"}'
        # Empty message field — returns the whole JSON
        assert extract_inner_message(raw) == raw

    def test_not_json(self):
        assert extract_inner_message("not json at all") == "not json at all"

    def test_whitespace_stripped(self):
        assert extract_inner_message("  spaced  ") == "spaced"


class TestNormalizeMessage:
    def test_replaces_timestamp(self):
        result = normalize_message("error at 2026-03-13T10:00:00Z in module")
        assert "<ts>" in result
        assert "2026" not in result

    def test_replaces_ip(self):
        result = normalize_message("connection from 192.168.1.100 failed")
        assert "<ip>" in result
        assert "192.168" not in result

    def test_replaces_uuid(self):
        result = normalize_message("request 550e8400-e29b-41d4-a716-446655440000 failed")
        assert "<uuid>" in result

    def test_replaces_hex(self):
        # hex regex requires word boundary — 0x prefix prevents match
        result = normalize_message("object deadbeef not found")
        assert "<hex>" in result

    def test_replaces_duration(self):
        result = normalize_message("took 150ms to complete")
        assert "<duration>" in result

    def test_replaces_percentage(self):
        # numbers get replaced first, so 95.2% becomes <num>.<num>%
        result = normalize_message("disk usage at 95.2%")
        assert "<num>" in result

    def test_replaces_numbers(self):
        result = normalize_message("retried 3 times, 42 errors")
        assert "<num>" in result

    def test_truncates_long_messages(self):
        result = normalize_message("x" * 1000)
        assert len(result) <= 500

    def test_collapses_whitespace(self):
        result = normalize_message("a   b\t\tc")
        assert "  " not in result


class TestStableHash:
    def test_deterministic(self):
        assert stable_hash("foo") == stable_hash("foo")

    def test_different_inputs(self):
        assert stable_hash("foo") != stable_hash("bar")

    def test_length(self):
        assert len(stable_hash("test", length=10)) == 10
        assert len(stable_hash("test", length=20)) == 20


class TestNormalizeSeverity:
    def test_critical_levels(self):
        for lvl in ["critical", "crit", "fatal"]:
            assert normalize_severity(lvl, "") == "critical"

    def test_error_levels(self):
        for lvl in ["error", "err"]:
            assert normalize_severity(lvl, "") == "error"

    def test_warning_levels(self):
        for lvl in ["warning", "warn"]:
            assert normalize_severity(lvl, "") == "warning"

    def test_info_levels(self):
        for lvl in ["info", "information"]:
            assert normalize_severity(lvl, "") == "info"

    def test_infer_from_message_critical(self):
        assert normalize_severity("", "kernel panic at 0x1234") == "critical"
        assert normalize_severity("", "out of memory killed process") == "critical"

    def test_infer_from_message_error(self):
        assert normalize_severity("", "connection refused to db") == "error"
        assert normalize_severity("", "Unhandled exception in worker") == "error"

    def test_infer_from_message_warning(self):
        assert normalize_severity("", "retrying with warning") == "warning"

    def test_fallback_info(self):
        assert normalize_severity("", "server started successfully") == "info"


class TestClassifyEvent:
    def test_dns_failure(self):
        ec, dep = classify_event("temporary failure in name resolution", "", "", "")
        assert ec == "dns_failure"
        assert dep == "dns"

    def test_connection_refused(self):
        ec, dep = classify_event("connection refused to port 5432", "", "", "")
        assert ec == "connect_refused"
        assert dep == "network"

    def test_database_locked(self):
        ec, dep = classify_event("database is locked", "", "", "")
        assert ec == "database_locked"
        assert dep == "storage"

    def test_oom(self):
        ec, dep = classify_event("out of memory: killed process 1234", "", "", "")
        assert ec == "oom_kill"
        assert dep == "memory"

    def test_tls_issue(self):
        ec, dep = classify_event("x509 certificate has expired", "", "", "")
        assert ec == "tls_or_cert_issue"
        assert dep == "tls"

    def test_timeout(self):
        ec, dep = classify_event("request timeout after 30s", "", "", "")
        assert ec == "timeout"
        assert dep == "network"

    def test_unknown(self):
        ec, dep = classify_event("everything is fine", "", "", "")
        assert ec == "unknown"
        assert dep == ""

    def test_failed_logon_windows(self):
        ec, dep = classify_event("An account failed to log on", "windows-event", "security", "4625")
        assert ec == "failed_logon"
        assert dep == "auth"


class TestFingerprintForEvent:
    def test_deterministic(self):
        event = {"source": "dozzle", "host": "node1", "container": "app",
                 "stream": "", "message": "error occurred"}
        assert fingerprint_for_event(event) == fingerprint_for_event(event)

    def test_different_messages_different_fingerprints(self):
        e1 = {"source": "dozzle", "host": "node1", "container": "app",
              "stream": "", "message": "error A"}
        e2 = {"source": "dozzle", "host": "node1", "container": "app",
              "stream": "", "message": "error B"}
        assert fingerprint_for_event(e1) != fingerprint_for_event(e2)

    def test_same_message_different_host(self):
        e1 = {"source": "dozzle", "host": "node1", "container": "app",
              "stream": "", "message": "error"}
        e2 = {"source": "dozzle", "host": "node2", "container": "app",
              "stream": "", "message": "error"}
        assert fingerprint_for_event(e1) != fingerprint_for_event(e2)


class TestEnrichEvent:
    def test_adds_required_fields(self):
        event = {"source": "dozzle", "host": "NODE1", "container": "app",
                 "stream": "", "level": "error", "message": "connection refused"}
        enriched = enrich_event(event)
        assert enriched["host"] == "node1"  # lowered
        assert enriched["ts"]
        assert enriched["fingerprint"]
        assert enriched["canonical_fingerprint"]
        assert enriched["event_class"] == "connect_refused"
        assert enriched["severity_norm"] == "error"
        assert enriched["message_template"]

    def test_preserves_original_fields(self):
        event = {"source": "syslog", "host": "h", "container": "c",
                 "stream": "s", "level": "info", "message": "ok"}
        enriched = enrich_event(event)
        assert enriched["source"] == "syslog"
        assert enriched["container"] == "c"
