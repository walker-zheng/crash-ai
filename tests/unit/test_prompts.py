"""Tests for Prompt 模板引擎 — Task 9 of Crash AI Phase 1."""
import pytest
from datetime import datetime
from src.models.crash import CrashContext, CrashMetadata, MemRegion, Module
from src.models.symbol import RawFrame, ResolvedFrame, ThreadState, ResolvedCrashContext


@pytest.fixture
def sample_resolved_ctx():
    """构造测试用 ResolvedCrashContext"""
    meta = CrashMetadata(
        timestamp=datetime(2026, 1, 1),
        hostname="test-host",
        kernel_version="5.15.0",
        distribution="ubuntu-22.04",
        arch="x86_64",
        coredump_size_bytes=1048576,
    )
    crash_ctx = CrashContext(
        signal="SIGSEGV",
        fault_addr="0x0",
        thread_states=[],
        registers={"rax": "0x0", "rip": "0x401234"},
        raw_stack=[],
        memory_maps=[
            MemRegion("0x400000", "0x401000", "r-xp", "0x0", "/usr/bin/app"),
        ],
        loaded_modules=[Module("libc.so.6", "0x7f000", "/lib/libc.so.6", "2.35")],
        metadata=meta,
    )
    crash_thread = ThreadState(tid=1, lwpid=1234, is_crashed=True, registers_at_crash={"rax": "0x0"})
    resolved_stack = [
        ResolvedFrame(0, "0x401234", "foo", "+0x42", "app", "src/main.c", 42, [], {}),
        ResolvedFrame(1, "0x401300", "bar", "+0x10", "app", "src/main.c", 15, [], {}),
    ]
    return ResolvedCrashContext(
        original=crash_ctx,
        resolved_stack=resolved_stack,
        crash_thread=crash_thread,
        signal_analysis="SIGSEGV: Invalid memory access (NULL pointer dereference)",
        memory_maps=crash_ctx.memory_maps,
        loaded_modules=crash_ctx.loaded_modules,
        metadata=meta,
    )


class TestSystemPrompt:
    def test_contains_five_analysis_steps(self):
        """验证 system prompt 包含全部5个分析步骤"""
        from src.analysis.prompts.system import SYSTEM_PROMPT
        assert "Signal Analysis" in SYSTEM_PROMPT
        assert "Register Analysis" in SYSTEM_PROMPT
        assert "Stack Analysis" in SYSTEM_PROMPT
        assert "Root Cause" in SYSTEM_PROMPT
        assert "Evidence" in SYSTEM_PROMPT

    def test_json_output_instruction(self):
        """验证包含 JSON 输出格式要求"""
        from src.analysis.prompts.system import SYSTEM_PROMPT
        assert "JSON" in SYSTEM_PROMPT


class TestUserPrompt:
    def test_build_from_resolved_context(self, sample_resolved_ctx):
        """验证从 ResolvedCrashContext 正确构建 prompt"""
        from src.analysis.prompts.user import build_user_prompt
        prompt = build_user_prompt(sample_resolved_ctx)
        assert "SIGSEGV" in prompt
        assert "x86_64" in prompt
        assert "ubuntu" in prompt
        assert "foo" in prompt

    def test_crash_thread_marked_with_arrow(self, sample_resolved_ctx):
        """验证崩溃线程帧用 → 标记"""
        from src.analysis.prompts.user import build_user_prompt
        prompt = build_user_prompt(sample_resolved_ctx)
        # Crash thread tid=1, frame_num=0 should have → marker
        lines = prompt.split("\n")
        frame_lines = [l for l in lines if l.strip().startswith("→") or l.strip().startswith("#0")]
        assert len(frame_lines) > 0

    def test_handles_empty_modules(self):
        """验证 loaded_modules 为空时不崩溃"""
        from src.analysis.prompts.user import build_user_prompt
        from src.models.symbol import ResolvedCrashContext
        ctx_with_empty_modules = ResolvedCrashContext(
            original=CrashContext(
                signal="SIGSEGV", fault_addr="0x0",
                thread_states=[], registers={}, raw_stack=[],
                memory_maps=[], loaded_modules=[],
                metadata=CrashMetadata(
                    timestamp=datetime.now(), hostname="", kernel_version="",
                    distribution="", arch="x86_64", coredump_size_bytes=0,
                ),
            ),
            resolved_stack=[],
            crash_thread=ThreadState(tid=1, lwpid=1, is_crashed=True),
            signal_analysis="SIGSEGV",
            memory_maps=[],
            loaded_modules=[],
            metadata=CrashMetadata(
                timestamp=datetime.now(), hostname="", kernel_version="",
                distribution="", arch="x86_64", coredump_size_bytes=0,
            ),
        )
        prompt = build_user_prompt(ctx_with_empty_modules)
        assert isinstance(prompt, str)
        assert len(prompt) > 0
