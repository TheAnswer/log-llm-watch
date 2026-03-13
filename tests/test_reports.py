"""Tests for services.reports — report text cleaning and prompt building."""
from services.reports import clean_daily_report_text


class TestCleanDailyReportText:
    def test_strips_thinking_tags(self):
        text = "<think>internal reasoning</think>\nOverall Status: Healthy"
        result = clean_daily_report_text(text)
        assert "<think>" not in result
        assert "internal reasoning" not in result
        assert result.startswith("Overall Status:")

    def test_strips_markdown(self):
        text = "Overall Status: Warning\n\n**Bold** text ### Heading"
        result = clean_daily_report_text(text)
        assert "**" not in result
        assert "###" not in result

    def test_strips_tables(self):
        text = "Overall Status: Warning\n|col1|col2|\n|---|---|\n|a|b|\nSummary here"
        result = clean_daily_report_text(text)
        assert "|" not in result

    def test_strips_conversational_endings(self):
        text = "Overall Status: Healthy\nAll good.\nWould you like more details?"
        result = clean_daily_report_text(text)
        assert "Would you like" not in result

    def test_adds_overall_status_if_missing(self):
        text = "Summary: everything is fine"
        result = clean_daily_report_text(text)
        assert result.startswith("Overall Status:")

    def test_preserves_good_text(self):
        text = "Overall Status: Warning\n\nSummary:\nSome issues detected."
        result = clean_daily_report_text(text)
        assert "Some issues detected" in result
