"""Tests for core.config — utilities."""
from datetime import timezone

from core.config import safe_json_loads, utcnow


class TestUtcnow:
    def test_returns_utc(self):
        now = utcnow()
        assert now.tzinfo == timezone.utc

    def test_returns_datetime(self):
        from datetime import datetime
        assert isinstance(utcnow(), datetime)


class TestSafeJsonLoads:
    def test_valid_json(self):
        assert safe_json_loads('{"a": 1}', {}) == {"a": 1}

    def test_valid_list(self):
        assert safe_json_loads('[1, 2]', []) == [1, 2]

    def test_invalid_json(self):
        assert safe_json_loads("not json", "default") == "default"

    def test_none_input(self):
        assert safe_json_loads(None, []) == []

    def test_empty_string(self):
        assert safe_json_loads("", {}) == {}
