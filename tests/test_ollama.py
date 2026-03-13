"""Tests for services.ollama — token extraction and context limit checks."""
from unittest.mock import patch
from io import StringIO

from services.ollama import _extract_token_stats, _check_context_limit


class TestExtractTokenStats:
    def test_extracts_counts(self):
        data = {"prompt_eval_count": 100, "eval_count": 50, "model": "llama3"}
        stats = _extract_token_stats(data)
        assert stats["prompt_tokens"] == 100
        assert stats["completion_tokens"] == 50
        assert stats["model"] == "llama3"

    def test_missing_fields(self):
        stats = _extract_token_stats({})
        assert stats["prompt_tokens"] == 0
        assert stats["completion_tokens"] == 0
        assert stats["model"] == ""

    def test_none_values(self):
        data = {"prompt_eval_count": None, "eval_count": None, "model": None}
        stats = _extract_token_stats(data)
        assert stats["prompt_tokens"] == 0
        assert stats["completion_tokens"] == 0


class TestCheckContextLimit:
    def test_no_warning_under_threshold(self, capsys):
        _check_context_limit({"prompt_eval_count": 100, "eval_count": 50}, 1000)
        assert "WARNING" not in capsys.readouterr().out

    def test_warning_near_limit(self, capsys):
        _check_context_limit({"prompt_eval_count": 9000, "eval_count": 600}, 10000)
        captured = capsys.readouterr().out
        assert "WARNING" in captured
        assert "context limit" in captured

    def test_no_warning_zero_ctx(self, capsys):
        _check_context_limit({"prompt_eval_count": 100, "eval_count": 50}, 0)
        assert "WARNING" not in capsys.readouterr().out
