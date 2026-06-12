"""pytest 共享 fixtures — mock LLM, sample contexts, env setup."""
import os
import sys
import pytest
from datetime import datetime
from unittest.mock import AsyncMock

# Ensure src/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


MOCK_LLM_JSON_RESPONSE = {
    "root_cause": {
        "category": "null-pointer",
        "description": "Dereference of NULL pointer at foo()+0x42",
        "crash_location": "src/main.c:42",
        "trigger_condition": "Passing NULL config pointer to init()",
    },
    "evidence": [
        {"type": "register", "description": "RAX register is 0x0", "relevance": "HIGH"},
        {"type": "stack", "description": "Frame #0 dereferences RAX", "relevance": "HIGH"},
        {"type": "source", "description": "config pointer unchecked at main.c:42", "relevance": "MEDIUM"},
    ],
    "fix_suggestion": "Add NULL check before dereferencing config pointer",
    "confidence": 0.92,
    "analysis_notes": "Symptom consistent with a simple missing guard clause",
}


@pytest.fixture
def mock_llm_json():
    """Mock LLM 返回标准 JSON 响应的 fixture。"""
    return MOCK_LLM_JSON_RESPONSE.copy()


@pytest.fixture
def sample_crash_metadata():
    """构造 CrashMetadata fixture。"""
    from src.models.crash import CrashMetadata
    return CrashMetadata(
        timestamp=datetime.now(),
        hostname="test-host",
        kernel_version="5.15.0-generic",
        distribution="ubuntu-22.04",
        arch="x86_64",
        coredump_size_bytes=1048576,
    )


@pytest.fixture
def sample_crash_ctx(sample_crash_metadata):
    """构造最小 CrashContext fixture。"""
    from src.models.crash import CrashContext
    return CrashContext(
        signal="SIGSEGV",
        fault_addr="0x0",
        thread_states=[],
        registers={"rax": "0x0", "rip": "0x401234"},
        raw_stack=[],
        memory_maps=[],
        loaded_modules=[],
        metadata=sample_crash_metadata,
    )


@pytest.fixture
def sample_resolved_ctx(sample_crash_ctx, sample_crash_metadata):
    """构造 ResolvedCrashContext fixture。"""
    from src.models.symbol import ResolvedCrashContext, ResolvedFrame, ThreadState

    crash_thread = ThreadState(
        tid=1, lwpid=1234, is_crashed=True,
        registers_at_crash={"rax": "0x0", "rip": "0x401234"},
    )

    return ResolvedCrashContext(
        original=sample_crash_ctx,
        resolved_stack=[
            ResolvedFrame(0, "0x401234", "foo", "+0x42", "app",
                         source_file="src/main.c", source_line=42),
            ResolvedFrame(1, "0x401300", "bar", "+0x10", "app",
                         source_file="src/main.c", source_line=15),
            ResolvedFrame(2, "0x401200", "main", "+0x08", "app",
                         source_file="src/main.c", source_line=8),
        ],
        crash_thread=crash_thread,
        signal_analysis="SIGSEGV: Invalid memory access (NULL pointer dereference)",
        memory_maps=sample_crash_ctx.memory_maps,
        loaded_modules=sample_crash_ctx.loaded_modules,
        metadata=sample_crash_metadata,
    )


@pytest.fixture
def sample_analysis_report():
    """构造 AnalysisReport fixture。"""
    from src.models.analysis import AnalysisReport, RootCause, Evidence
    return AnalysisReport(
        crash_id="test-crash-001",
        timestamp=datetime.now(),
        root_cause=RootCause(
            category="null-pointer",
            description="NULL dereference at foo()+0x42",
            crash_location="src/main.c:42",
            trigger_condition="Missing NULL check for config pointer",
        ),
        evidence=[
            Evidence("register", "RAX register is 0x0", "HIGH"),
            Evidence("stack", "Frame #0 dereferences RAX", "HIGH"),
        ],
        fix_suggestion="Add NULL check before dereferencing config pointer",
        confidence=0.92,
        analysis_notes=None,
        raw_llm_response='{"root_cause": {...}}',
    )


@pytest.fixture
def env_setup(monkeypatch):
    """设置最小环境变量 (支持测试模式)。"""
    monkeypatch.setenv("CRASHAI_DEEPSEEK_API_KEY", "sk-test-deepseek")
    monkeypatch.setenv("CRASHAI_DEFAULT_PROVIDER", "deepseek")
    # Force reload config
    import src.config
    import importlib
    importlib.reload(src.config)
    return os.environ
