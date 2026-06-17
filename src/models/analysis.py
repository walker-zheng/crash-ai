"""Analysis output models."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class RootCause:
    """根因分析"""

    category: str  # null-pointer / use-after-free / double-free / buffer-overflow / stack-overflow / race-condition / unknown
    description: str
    crash_location: str  # file:line
    trigger_condition: str


@dataclass
class Evidence:
    """证据条目"""

    type: str  # register / memory / stack / source / logic
    description: str
    relevance: str  # HIGH / MEDIUM / LOW


@dataclass
class AnalysisReport:
    """最终分析报告"""

    crash_id: str
    timestamp: datetime
    root_cause: RootCause
    evidence: List[Evidence]
    fix_suggestion: str
    confidence: float  # 0.0 - 1.0
    raw_llm_response: str
    analysis_notes: Optional[str] = None  # 分析备注


@dataclass
class CrossValidation:
    """跨源交叉验证结果"""

    source_a: str
    source_b: str
    consensus: str
    contradiction: Optional[str] = None


@dataclass
class CorrelatedContext:
    """关联上下文分析结果"""

    timeline_alignment: list = field(default_factory=list)
    register_var_map: dict = field(default_factory=dict)
    lock_analysis: Optional[str] = None
    memory_analysis: Optional[str] = None
    danger_patterns: List[str] = field(default_factory=list)
    suggested_category: str = ""  # CorrelationEngine 确定性推断的崩溃类别
