"""Terminal colour output — uses ANSI escape codes."""
from src.models.analysis import AnalysisReport

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
GRAY = "\033[90m"


def format_terminal(report: AnalysisReport) -> str:
    """Produce a terminal-friendly colourised output."""
    lines = []
    lines.append(f"{BOLD}{BLUE}╔══════════════════════════════════════╗{RESET}")
    lines.append(f"{BOLD}{BLUE}║  Crash AI Analysis Report           ║{RESET}")
    lines.append(f"{BOLD}{BLUE}╚══════════════════════════════════════╝{RESET}")
    lines.append("")
    lines.append(f"{BOLD}Crash ID:{RESET} {report.crash_id}")
    lines.append(f"{GRAY}Timestamp:{RESET} {report.timestamp.isoformat()}")
    lines.append("")

    # Root Cause
    lines.append(f"{BOLD}{RED}═══ Root Cause ═══{RESET}")
    lines.append(f"  {BOLD}Category:{RESET} {report.root_cause.category}")
    lines.append(f"  {BOLD}Location:{RESET} {report.root_cause.crash_location}")
    lines.append(f"  {BOLD}Description:{RESET} {report.root_cause.description}")
    lines.append(f"  {BOLD}Trigger:{RESET} {report.root_cause.trigger_condition}")
    lines.append("")

    # Evidence
    lines.append(f"{BOLD}{YELLOW}═══ Evidence Chain ═══{RESET}")
    for i, ev in enumerate(report.evidence, 1):
        relevance_color = RED if ev.relevance == "HIGH" else YELLOW if ev.relevance == "MEDIUM" else GRAY
        lines.append(
            f"  {i}. [{relevance_color}{ev.relevance}{RESET}] {ev.type}: {ev.description}"
        )
    lines.append("")

    # Fix Suggestion
    lines.append(f"{BOLD}{GREEN}═══ Fix Suggestion ═══{RESET}")
    lines.append(f"  {report.fix_suggestion}")
    lines.append("")

    # Confidence
    lines.append(f"{BOLD}{CYAN}═══ Metadata ═══{RESET}")
    confidence_color = GREEN if report.confidence >= 0.8 else YELLOW if report.confidence >= 0.5 else RED
    lines.append(f"  Confidence: {confidence_color}{report.confidence:.0%}{RESET}")

    if report.analysis_notes:
        lines.append(f"  Notes: {report.analysis_notes}")

    return "\n".join(lines)
