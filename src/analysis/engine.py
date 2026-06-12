"""AI 分析引擎 — 编排 5 步推理链。

工作流:
  1. Cross-validation (CorrelationEngine, no LLM)
  2. Build prompts (system + user)
  3. Call LLM via LLMRouter with retry
  4. Parse LLM JSON response into AnalysisReport
  5. Fallback if LLM unavailable
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from src.config import Config
from src.models.symbol import ResolvedCrashContext
from src.models.analysis import (
    AnalysisReport,
    RootCause,
    Evidence,
    CorrelatedContext,
)
from src.analysis.llm_router import LLMRouter
from src.analysis.correlation import CorrelationEngine
from src.analysis.prompts.system import SYSTEM_PROMPT
from src.analysis.prompts.user import build_user_prompt
from src.utils.retry import retry_async
from src.errors import AnalysisIncompleteError


class AnalysisEngine:
    """AI 分析引擎。

    5 步推理链编排:
    1. Signal Analysis  — LLM 分析信号类型
    2. Register Analysis — LLM 解读寄存器异常
    3. Stack Analysis    — LLM 追踪跨帧数据流
    4. Root Cause        — LLM 推断根因类别
    5. Evidence Extract  — LLM 提取证据链

    配合多源交叉验证 (CorrelationEngine) 增强置信度。
    """

    def __init__(
        self,
        config: Config,
        router: Optional[LLMRouter] = None,
        provider: Optional[str] = None,
    ):
        self.config = config
        self.router = router or LLMRouter(config, provider=provider)
        self.correlation = CorrelationEngine()

    async def analyze(self, ctx: ResolvedCrashContext) -> AnalysisReport:
        """执行完整 AI 分析流程。

        流程:
        1. CorrelationEngine.validate() → 多源交叉验证
        2. build_user_prompt() → 构建 LLM 输入
        3. LLMRouter.analyze() → 调用 LLM (含重试)
        4. 解析 LLM JSON 响应 → AnalysisReport
        5. 若非有效 JSON: retry (最多3次) → 降级输出
        """
        crash_id = str(uuid.uuid4())[:12]

        # 1. Cross-validation (no LLM needed)
        correlated = self.correlation.validate(ctx.original)

        # 2. Build prompts
        system = SYSTEM_PROMPT
        user = build_user_prompt(ctx)

        # 3. Append correlation findings to user prompt
        if correlated.danger_patterns:
            user += "\n\n## Pre-analysis (heuristic)\n"
            for pattern in correlated.danger_patterns:
                user += f"  - {pattern}\n"

        # 4. Call LLM with retry
        try:
            llm_response = await retry_async(
                self.router.analyze,
                system,
                user,
                max_retries=3,
                base_delay=1.0,
                exceptions=(json.JSONDecodeError, AnalysisIncompleteError),
            )
        except Exception as exc:
            return self._build_fallback_report(ctx, crash_id, str(exc))

        # 5. Parse response
        return self._parse_llm_response(llm_response, crash_id)

    def _parse_llm_response(self, raw: dict, crash_id: str) -> AnalysisReport:
        """将 LLM JSON 响应解析为 AnalysisReport。

        对 LLM 输出做类型校验 + 字段补全 (缺失字段填默认值)。
        """
        rc_data = raw.get("root_cause", {})
        root_cause = RootCause(
            category=str(rc_data.get("category", "unknown")),
            description=str(rc_data.get("description", "No description provided")),
            crash_location=str(rc_data.get("crash_location", "unknown")),
            trigger_condition=str(rc_data.get("trigger_condition", "unknown")),
        )

        evidence = []
        for ev_data in raw.get("evidence", []):
            evidence.append(Evidence(
                type=str(ev_data.get("type", "unknown")),
                description=str(ev_data.get("description", "")),
                relevance=str(ev_data.get("relevance", "MEDIUM")),
            ))

        confidence = raw.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)):
            confidence = 0.5
        confidence = max(0.0, min(1.0, float(confidence)))

        return AnalysisReport(
            crash_id=crash_id,
            timestamp=datetime.now(timezone.utc),
            root_cause=root_cause,
            evidence=evidence,
            fix_suggestion=str(raw.get("fix_suggestion", "No fix suggestion provided")),
            confidence=confidence,
            analysis_notes=raw.get("analysis_notes"),
            raw_llm_response=json.dumps(raw, ensure_ascii=False),
        )

    def _build_fallback_report(
        self, ctx: ResolvedCrashContext, crash_id: str, error: str
    ) -> AnalysisReport:
        """LLM 不可用时的降级报告 — 仅包含符号解析结果, 无 AI 分析。"""
        crash_location = "unknown"
        fallback_desc = "No stack available"
        if ctx.resolved_stack:
            crash_location = (
                f"{ctx.resolved_stack[0].source_file}:{ctx.resolved_stack[0].source_line}"
            )
            fallback_desc = f"Crash in {ctx.resolved_stack[0].function}"

        return AnalysisReport(
            crash_id=crash_id,
            timestamp=datetime.now(timezone.utc),
            root_cause=RootCause(
                category="unknown",
                description=f"LLM analysis unavailable: {error}",
                crash_location=crash_location,
                trigger_condition="Unable to determine (LLM unavailable)",
            ),
            evidence=[
                Evidence(
                    type="stack",
                    description=fallback_desc,
                    relevance="MEDIUM",
                )
            ],
            fix_suggestion="LLM analysis unavailable. Review crash manually with GDB.",
            confidence=0.0,
            analysis_notes=f"Fallback report — LLM error: {error}",
            raw_llm_response=json.dumps({"error": error}),
        )
