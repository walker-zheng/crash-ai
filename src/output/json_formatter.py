"""JSON formatter."""
import json
from dataclasses import asdict
from src.models.analysis import AnalysisReport


def format_json(report: AnalysisReport, indent: int = 2) -> str:
    """Serialize AnalysisReport to a formatted JSON string."""
    return json.dumps(asdict(report), indent=indent, default=str, ensure_ascii=False)
