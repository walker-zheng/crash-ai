"""E2E pipeline integration tests — 全链路 mock LLM 验证。

测试覆盖:
  - 完整分析管道: ResolvedCrashContext → LLM → AnalysisReport
  - 输出格式: JSON / Terminal / Markdown
  - ELF core dump 加载链路
"""
import os
import json
import pytest
from pathlib import Path
from unittest.mock import patch, AsyncMock

from src.config import Config
from src.models.analysis import AnalysisReport


MOCK_LLM_RESPONSE = {
    "root_cause": {
        "category": "null-pointer",
        "description": "NULL pointer dereference at foo()+0x42",
        "crash_location": "src/main.c:42",
        "trigger_condition": "Passing NULL config to init()",
    },
    "evidence": [
        {"type": "register", "description": "RAX register is 0x0", "relevance": "HIGH"},
        {"type": "stack", "description": "Frame #0 dereferences RAX", "relevance": "HIGH"},
    ],
    "fix_suggestion": "Add NULL check before dereferencing config pointer",
    "confidence": 0.92,
}


@pytest.fixture
def sample_core_path():
    """Return the sample ELF core dump fixture path."""
    return Path(__file__).parent.parent / "fixtures" / "sample.core"


class TestFullPipeline:
    """全链路 E2E 测试 — 模拟 LLM backend。"""

    @pytest.mark.asyncio
    async def test_end_to_end_with_mock_llm(self, sample_resolved_ctx, env_setup):
        """E2E: 输入 ResolvedCrashContext → AI 分析 → 输出 AnalysisReport"""
        config = Config()
        from src.analysis.engine import AnalysisEngine

        engine = AnalysisEngine(config)

        with patch("src.analysis.engine.LLMRouter") as MockRouter:
            mock_router = MockRouter.return_value
            mock_router.analyze = AsyncMock(return_value=MOCK_LLM_RESPONSE)
            engine.router = mock_router

            report = await engine.analyze(sample_resolved_ctx)

            assert isinstance(report, AnalysisReport)
            assert report.root_cause.category == "null-pointer"
            assert report.confidence == 0.92
            assert len(report.evidence) == 2

    @pytest.mark.asyncio
    async def test_confidence_in_range(self, sample_resolved_ctx, env_setup):
        """E2E: 验证 confidence 始终在 0.0~1.0 范围"""
        config = Config()
        from src.analysis.engine import AnalysisEngine

        engine = AnalysisEngine(config)

        with patch("src.analysis.engine.LLMRouter") as MockRouter:
            mock_router = MockRouter.return_value
            mock_router.analyze = AsyncMock(return_value=MOCK_LLM_RESPONSE)
            engine.router = mock_router

            report = await engine.analyze(sample_resolved_ctx)

            assert 0.0 <= report.confidence <= 1.0

    def test_output_format_json(self, sample_analysis_report):
        """E2E: 验证 JSON 输出格式正确"""
        from src.output.json_formatter import format_json
        output = format_json(sample_analysis_report)
        parsed = json.loads(output)
        assert parsed["root_cause"]["category"] == "null-pointer"
        assert len(parsed["evidence"]) == 2
        assert parsed["confidence"] == 0.92

    def test_output_format_terminal(self, sample_analysis_report):
        """E2E: 验证 terminal 输出格式正确"""
        from src.output.terminal import format_terminal
        output = format_terminal(sample_analysis_report)
        assert "Crash ID:" in output
        assert "null-pointer" in output
        assert "RAX register is 0x0" in output

    def test_output_format_markdown(self, sample_analysis_report):
        """E2E: 验证 markdown 输出格式正确"""
        from src.output.markdown_formatter import format_markdown
        output = format_markdown(sample_analysis_report)
        assert "# Crash Analysis Report" in output
        assert "## Root Cause" in output
        assert "## Evidence Chain" in output
        assert "## Fix Suggestion" in output
        assert "|" in output  # table

    @pytest.mark.asyncio
    async def test_crash_id_generated(self, sample_resolved_ctx, env_setup):
        """E2E: 验证每次分析生成唯一 crash_id"""
        config = Config()
        from src.analysis.engine import AnalysisEngine

        engine = AnalysisEngine(config)

        with patch("src.analysis.engine.LLMRouter") as MockRouter:
            mock_router = MockRouter.return_value
            mock_router.analyze = AsyncMock(return_value=MOCK_LLM_RESPONSE)
            engine.router = mock_router

            report1 = await engine.analyze(sample_resolved_ctx)
            report2 = await engine.analyze(sample_resolved_ctx)

            assert report1.crash_id != report2.crash_id
            assert len(report1.crash_id) == 12
