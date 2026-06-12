"""Markdown report formatter."""
from src.models.analysis import AnalysisReport


def format_markdown(report: AnalysisReport) -> str:
    """Generate a Markdown-format analysis report."""
    lines = []
    lines.append(f"# Crash Analysis Report: {report.crash_id}")
    lines.append("")
    lines.append(f"**Timestamp:** {report.timestamp.isoformat()}")
    lines.append(f"**Confidence:** {report.confidence:.0%}")
    lines.append("")

    lines.append("## Root Cause Analysis")
    lines.append("")
    lines.append(f"- **Category:** `{report.root_cause.category}`")
    lines.append(f"- **Location:** `{report.root_cause.crash_location}`")
    lines.append(f"- **Description:** {report.root_cause.description}")
    lines.append(f"- **Trigger Condition:** {report.root_cause.trigger_condition}")
    lines.append("")

    lines.append("## Evidence Chain")
    lines.append("")
    lines.append("| # | Type | Relevance | Description |")
    lines.append("|---|------|-----------|-------------|")
    for i, ev in enumerate(report.evidence, 1):
        lines.append(f"| {i} | {ev.type} | **{ev.relevance}** | {ev.description} |")
    lines.append("")

    lines.append("## Fix Suggestion")
    lines.append("")
    lines.append(report.fix_suggestion)
    lines.append("")

    if report.analysis_notes:
        lines.append("## Analysis Notes")
        lines.append("")
        lines.append(report.analysis_notes)

    return "\n".join(lines)
