"""Tests for output formatters — Task 12 of Crash AI Phase 1."""
import json
import pytest
from datetime import datetime
from src.models.analysis import AnalysisReport, RootCause, Evidence


@pytest.fixture
def sample_report():
    """Construct a test AnalysisReport."""
    rc = RootCause(
        category="null-pointer",
        description="NULL pointer dereference at foo()+0x42",
        crash_location="src/main.c:42",
        trigger_condition="Passing NULL config to init()"
    )
    evidence = [
        Evidence("register", "RAX is 0x0", "HIGH"),
        Evidence("stack", "Frame #0 dereferences RAX", "HIGH"),
        Evidence("source", "config pointer not checked before deref", "MEDIUM"),
    ]
    return AnalysisReport(
        crash_id="crash-2026-001",
        timestamp=datetime(2026, 1, 15, 10, 30, 0),
        root_cause=rc,
        evidence=evidence,
        fix_suggestion="Add NULL check before dereferencing config pointer in init()",
        confidence=0.92,
        analysis_notes="Likely introduced in commit abc123",
        raw_llm_response='{"root_cause": {...}}',
    )


class TestJSONFormatter:
    def test_valid_json_output(self, sample_report):
        """Verify output is valid JSON string."""
        from src.output.json_formatter import format_json
        output = format_json(sample_report)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_contains_all_fields(self, sample_report):
        """Verify JSON contains root_cause/evidence/fix_suggestion/confidence."""
        from src.output.json_formatter import format_json
        output = format_json(sample_report)
        parsed = json.loads(output)
        assert "root_cause" in parsed
        assert "evidence" in parsed
        assert "fix_suggestion" in parsed
        assert "confidence" in parsed

    def test_indent_parameter(self, sample_report):
        """Verify indent parameter takes effect."""
        from src.output.json_formatter import format_json
        output_2 = format_json(sample_report, indent=2)
        output_4 = format_json(sample_report, indent=4)
        assert len(output_4) > len(output_2)


class TestTerminalFormatter:
    def test_contains_ansi_escape_codes(self, sample_report):
        """Verify output contains ANSI color escape codes."""
        from src.output.terminal import format_terminal
        output = format_terminal(sample_report)
        assert "\033[" in output or "\\033[" in output or "\\x1b" in output.lower() or "\x1b" in output

    def test_contains_crash_info(self, sample_report):
        """Verify output contains crash information."""
        from src.output.terminal import format_terminal
        output = format_terminal(sample_report)
        assert "null-pointer" in output or "NULL" in output


class TestMarkdownFormatter:
    def test_contains_markdown_headers(self, sample_report):
        """Verify output contains # and ## headers."""
        from src.output.markdown_formatter import format_markdown
        output = format_markdown(sample_report)
        assert "# " in output
        assert "## " in output

    def test_evidence_as_table(self, sample_report):
        """Verify evidence is output as Markdown table."""
        from src.output.markdown_formatter import format_markdown
        output = format_markdown(sample_report)
        assert "|" in output  # Table marker

    def test_contains_confidence(self, sample_report):
        """Verify output contains confidence value."""
        from src.output.markdown_formatter import format_markdown
        output = format_markdown(sample_report)
        assert "0.92" in output or "92%" in output or "92" in output
