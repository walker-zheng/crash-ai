"""Integration tests for AnalysisEngine — 5-step reasoning chain orchestrator."""
import json
from datetime import datetime
from unittest.mock import patch, AsyncMock

import pytest

from src.models.crash import CrashContext, CrashMetadata, MemRegion, Module
from src.models.symbol import RawFrame, ResolvedFrame, ThreadState, ResolvedCrashContext
from src.models.analysis import AnalysisReport


MOCK_LLM_JSON_RESPONSE = {
    "root_cause": {
        "category": "null-pointer",
        "description": "NULL pointer dereference at foo()+0x42",
        "crash_location": "src/main.c:42",
        "trigger_condition": "Passing NULL config pointer to init()",
    },
    "evidence": [
        {"type": "register", "description": "RAX register is 0x0", "relevance": "HIGH"},
        {"type": "stack", "description": "Frame #0 dereferences RAX at 0x0", "relevance": "HIGH"},
    ],
    "fix_suggestion": "Add NULL check before dereferencing config pointer",
    "confidence": 0.92,
}


@pytest.fixture
def sample_resolved_ctx():
    """Construct a test ResolvedCrashContext (NULL deref scenario)."""
    meta = CrashMetadata(
        timestamp=datetime.now(), hostname="test", kernel_version="5.15",
        distribution="ubuntu", arch="x86_64", coredump_size_bytes=1024,
    )
    crash_ctx = CrashContext(
        signal="SIGSEGV", fault_addr="0x0",
        thread_states=[], registers={"rax": "0x0", "rip": "0x401234"},
        raw_stack=[RawFrame(0, "0x401234", "foo", "+0x42", "app")],
        memory_maps=[],
        loaded_modules=[],
        metadata=meta,
    )
    crash_thread = ThreadState(tid=0, lwpid=1234, is_crashed=True,
                               registers_at_crash={"rax": "0x0"})
    return ResolvedCrashContext(
        original=crash_ctx,
        resolved_stack=[
            ResolvedFrame(0, "0x401234", "foo", "+0x42", "app",
                          source_file="src/main.c", source_line=42),
        ],
        crash_thread=crash_thread,
        signal_analysis="SIGSEGV: Invalid memory access",
        memory_maps=crash_ctx.memory_maps,
        loaded_modules=crash_ctx.loaded_modules,
        metadata=meta,
    )


@pytest.fixture
def config_with_key():
    """Create a Config instance with a test API key set."""
    with patch.dict("os.environ", {
        "CRASHAI_DEEPSEEK_API_KEY": "sk-test",
        "CRASHAI_DEFAULT_PROVIDER": "deepseek",
    }):
        from src.config import Config
        return Config()


class TestAnalysisEngine:
    """AnalysisEngine integration tests — mock LLM backend."""

    @pytest.mark.asyncio
    async def test_full_analysis_with_mock_llm(self, sample_resolved_ctx, config_with_key):
        """Full analysis flow: ResolvedCrashContext in -> AnalysisReport out."""
        from src.analysis.engine import AnalysisEngine

        engine = AnalysisEngine(config_with_key)

        with patch("src.analysis.engine.LLMRouter") as MockRouter:
            mock_router = MockRouter.return_value
            mock_router.analyze = AsyncMock(return_value=MOCK_LLM_JSON_RESPONSE)
            engine.router = mock_router

            report = await engine.analyze(sample_resolved_ctx)

            assert isinstance(report, AnalysisReport)
            assert report.root_cause.category == "null-pointer"
            assert report.root_cause.crash_location == "src/main.c:42"
            assert len(report.evidence) == 2

    @pytest.mark.asyncio
    async def test_confidence_score_in_range(self, sample_resolved_ctx, config_with_key):
        """Verify confidence is always in 0.0..1.0 range."""
        from src.analysis.engine import AnalysisEngine

        engine = AnalysisEngine(config_with_key)
        with patch("src.analysis.engine.LLMRouter") as MockRouter:
            mock_router = MockRouter.return_value
            mock_router.analyze = AsyncMock(return_value=MOCK_LLM_JSON_RESPONSE)
            engine.router = mock_router

            report = await engine.analyze(sample_resolved_ctx)
            assert 0.0 <= report.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_evidence_not_empty(self, sample_resolved_ctx, config_with_key):
        """Verify evidence list is non-empty."""
        from src.analysis.engine import AnalysisEngine

        engine = AnalysisEngine(config_with_key)
        with patch("src.analysis.engine.LLMRouter") as MockRouter:
            mock_router = MockRouter.return_value
            mock_router.analyze = AsyncMock(return_value=MOCK_LLM_JSON_RESPONSE)
            engine.router = mock_router

            report = await engine.analyze(sample_resolved_ctx)
            assert len(report.evidence) > 0

    @pytest.mark.asyncio
    async def test_fallback_on_partial_response(self, sample_resolved_ctx, config_with_key):
        """Verify graceful fallback when LLM returns partial/invalid JSON fields."""
        from src.analysis.engine import AnalysisEngine

        engine = AnalysisEngine(config_with_key)
        with patch("src.analysis.engine.LLMRouter") as MockRouter:
            mock_router = MockRouter.return_value
            mock_router.analyze = AsyncMock(return_value={"invalid": "not a report"})
            engine.router = mock_router

            report = await engine.analyze(sample_resolved_ctx)
            assert isinstance(report, AnalysisReport)
            # Should have default values for missing fields
            assert report.root_cause.category == "unknown"
            assert report.confidence == 0.5  # default when missing
