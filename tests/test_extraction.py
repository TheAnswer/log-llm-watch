"""Tests for core.extraction — event extraction from webhook payloads."""
from core.extraction import (
    extract_dozzle_event,
    extract_syslog_event,
    extract_windows_event,
    normalize_windows_level,
)


class TestExtractDozzleEvent:
    def test_basic_payload(self):
        payload = {
            "text": "my-container",
            "blocks": [
                {"text": {"text": "Something went wrong"}},
                {"elements": [{"text": "Host: node1 | other"}]},
            ],
        }
        event = extract_dozzle_event(payload)
        assert event["source"] == "dozzle-webhook"
        assert event["container"] == "my-container"
        assert event["host"] == "node1"
        assert "Something went wrong" in event["message"]

    def test_non_dict_payload(self):
        event = extract_dozzle_event("just a string")
        assert event["source"] == "dozzle-webhook"
        assert event["container"] == "unknown"

    def test_error_level_detection(self):
        payload = {
            "text": "app",
            "blocks": [{"text": {"text": "Unhandled exception in worker"}}],
        }
        event = extract_dozzle_event(payload)
        assert event["level"] == "error"

    def test_critical_level_detection(self):
        payload = {
            "text": "app",
            "blocks": [{"text": {"text": "fatal: out of memory"}}],
        }
        event = extract_dozzle_event(payload)
        assert event["level"] == "critical"

    def test_container_name_stripped_from_message(self):
        payload = {
            "text": "nginx",
            "blocks": [{"text": {"text": "nginx\nconnection reset by peer"}}],
        }
        event = extract_dozzle_event(payload)
        assert not event["message"].startswith("nginx")


class TestNormalizeWindowsLevel:
    def test_level_name(self):
        assert normalize_windows_level(None, "Error") == "error"
        assert normalize_windows_level(None, "Warning") == "warning"
        assert normalize_windows_level(None, "Information") == "info"
        assert normalize_windows_level(None, "Critical") == "critical"

    def test_level_value(self):
        assert normalize_windows_level(1) == "critical"
        assert normalize_windows_level(2) == "error"
        assert normalize_windows_level(3) == "warning"
        assert normalize_windows_level(4) == "info"

    def test_unknown_level(self):
        assert normalize_windows_level(99) == ""

    def test_level_name_takes_precedence(self):
        assert normalize_windows_level(4, "Error") == "error"


class TestExtractWindowsEvent:
    def test_basic_payload(self):
        payload = {
            "Hostname": "WIN-SERVER",
            "Channel": "Application",
            "ProviderName": "MyApp",
            "EventID": 1000,
            "Message": "Application crashed",
            "SeverityValue": 2,
        }
        event = extract_windows_event(payload)
        assert event["source"] == "windows-event"
        assert event["host"] == "win-server"
        assert event["container"] == "Application"
        assert event["level"] == "error"
        assert "Application crashed" in event["message"]
        assert "MyApp" in event["stream"]
        assert "1000" in event["stream"]

    def test_security_failed_logon(self):
        payload = {
            "Hostname": "DC01",
            "Channel": "Security",
            "EventID": 4625,
            "Message": "An account failed to log on",
        }
        event = extract_windows_event(payload)
        assert event["level"] == "warning"

    def test_non_dict_payload(self):
        event = extract_windows_event(42)
        assert event["source"] == "windows-event"
        assert "42" in event["message"]


class TestExtractSyslogEvent:
    def test_basic_payload(self):
        payload = {
            "host": "ROUTER",
            "program": "sshd",
            "message": "Failed password for root from 10.0.0.1",
        }
        event = extract_syslog_event(payload)
        assert event["source"] == "syslog"
        assert event["host"] == "router"
        assert event["container"] == "sshd"
        assert event["level"] == "error"  # "failed" keyword

    def test_critical_detection(self):
        payload = {"host": "h", "message": "kernel panic - not syncing"}
        event = extract_syslog_event(payload)
        assert event["level"] == "critical"

    def test_non_dict_payload(self):
        event = extract_syslog_event([1, 2, 3])
        assert event["source"] == "syslog"
