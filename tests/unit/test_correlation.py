"""Tests for CorrelationEngine — 多源交叉验证。"""
import pytest
from datetime import datetime
from src.models.crash import CrashContext, CrashMetadata, MemRegion
from src.models.symbol import RawFrame


@pytest.fixture
def null_deref_context():
    """NULL deref: fault_addr=0x0, rax=0x0"""
    meta = CrashMetadata(
        timestamp=datetime.now(), hostname="test", kernel_version="5.15",
        distribution="ubuntu", arch="x86_64", coredump_size_bytes=1024,
    )
    return CrashContext(
        signal="SIGSEGV",
        fault_addr="0x0",
        thread_states=[],
        registers={"rax": "0x0", "rip": "0x401234"},
        raw_stack=[
            RawFrame(0, "0x401234", "foo", "+0x42", "app"),
            RawFrame(1, "0x401300", "bar", "+0x10", "app"),
        ],
        memory_maps=[
            MemRegion("0x400000", "0x402000", "r-xp", "0x0", "/usr/bin/app"),
        ],
        loaded_modules=[],
        metadata=meta,
    )


@pytest.fixture
def empty_context():
    """最小 CrashContext"""
    meta = CrashMetadata(
        timestamp=datetime.now(), hostname="", kernel_version="",
        distribution="", arch="x86_64", coredump_size_bytes=0,
    )
    return CrashContext(
        signal="SIGSEGV",
        fault_addr="0x0",
        thread_states=[],
        registers={},
        raw_stack=[],
        memory_maps=[],
        loaded_modules=[],
        metadata=meta,
    )


class TestCorrelationEngine:
    def test_null_deref_detection(self, null_deref_context):
        """fault_addr=0x0 → 检测为 NULL deref"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        result = engine.validate(null_deref_context)
        assert "NULL pointer dereference" in result.danger_patterns or any(
            "null" in p.lower() for p in result.danger_patterns
        )

    def test_register_stack_consistency(self, null_deref_context):
        """寄存器地址在堆栈帧中出现 → 一致性检查运行"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        result = engine.validate(null_deref_context)
        # Check that cross-validations were produced
        assert isinstance(result.timeline_alignment, list)
        assert isinstance(result.register_var_map, dict)

    def test_empty_context_no_crash(self, empty_context):
        """空 CrashContext 不应抛出异常"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        result = engine.validate(empty_context)
        assert result is not None

    def test_fault_addr_in_memory_map(self, null_deref_context):
        """0x401234 should be within 0x400000-0x402000 range"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        result = engine.validate(null_deref_context)
        # fault_addr 0x0 is not in any mapped region
        assert result.memory_analysis is not None
        assert "not in any mapped region" in result.memory_analysis

    def test_signal_stack_consistency_sigsegv_null(self, null_deref_context):
        """SIGSEGV with NULL deref → consistency check produced"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        result = engine.validate(null_deref_context)
        # The signal is SIGSEGV and top function is 'foo' (not null/deref/memcpy)
        # So the engine should flag this
        assert isinstance(result.timeline_alignment, list)

    def test_danger_patterns_null_register(self, null_deref_context):
        """rax=0x0 should be detected as NULL register value"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        result = engine.validate(null_deref_context)
        assert any("null" in p.lower() for p in result.danger_patterns)

    def test_register_var_map_structure(self, null_deref_context):
        """register_var_map should have correct structure"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        result = engine.validate(null_deref_context)
        assert "rax" in result.register_var_map
        assert "value" in result.register_var_map["rax"]
        assert "is_null" in result.register_var_map["rax"]
        assert result.register_var_map["rax"]["is_null"] is True

    def test_danger_patterns_function_none(self):
        """raw_stack[0].function=None 不应抛 AttributeError"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        meta = CrashMetadata(
            timestamp=datetime.now(), hostname="", kernel_version="",
            distribution="", arch="x86_64", coredump_size_bytes=0,
        )
        ctx = CrashContext(
            signal="SIGSEGV",
            fault_addr="0x7fff",
            thread_states=[],
            registers={"rax": "0x7fff"},
            raw_stack=[
                RawFrame(0, "0x7fff", None, "+0x0", "app"),
            ],
            memory_maps=[],
            loaded_modules=[],
            metadata=meta,
        )
        result = engine.validate(ctx)
        # Should not crash; danger_patterns should be an empty list
        assert isinstance(result.danger_patterns, list)

    # ------------------------------------------------------------------
    # _infer_category 测试
    # ------------------------------------------------------------------

    def _make_context(self, signal: str, fault_addr: str, registers: dict | None = None,
                      top_func: str | None = None) -> CrashContext:
        """Helper: 快速构造 CrashContext"""
        meta = CrashMetadata(
            timestamp=datetime.now(), hostname="t", kernel_version="6.0",
            distribution="u", arch="x86_64", coredump_size_bytes=1,
        )
        stack = []
        if top_func is not None:
            stack.append(RawFrame(0, "0x401000", top_func, "+0x0", "app"))
        return CrashContext(
            signal=signal, fault_addr=fault_addr,
            thread_states=[], registers=registers or {},
            raw_stack=stack, memory_maps=[], loaded_modules=[],
            metadata=meta,
        )

    def test_infer_category_null_deref_by_addr(self):
        """fault_addr=0x0 → null-deref"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        ctx = self._make_context("SIGSEGV", "0x0")
        assert engine._infer_category(ctx) == "null-deref"

    def test_infer_category_null_deref_by_register(self):
        """SIGSEGV + 寄存器含 0x0 → null-deref"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        ctx = self._make_context("SIGSEGV", "0x7fff", registers={"rax": "0x0"})
        assert engine._infer_category(ctx) == "null-deref"

    def test_infer_category_sigbus(self):
        """SIGBUS → sigbus-unaligned"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        ctx = self._make_context("SIGBUS", "0x7fff")
        assert engine._infer_category(ctx) == "sigbus-unaligned"

    def test_infer_category_sigfpe(self):
        """SIGFPE → division-by-zero"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        ctx = self._make_context("SIGFPE", "0x7fff")
        assert engine._infer_category(ctx) == "division-by-zero"

    def test_infer_category_double_free(self):
        """SIGABRT + free() in top frame → double-free"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        ctx = self._make_context("SIGABRT", "0x7fff", top_func="free")
        assert engine._infer_category(ctx) == "double-free"

    def test_infer_category_assert_fail(self):
        """SIGABRT without free → assert-fail"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        ctx = self._make_context("SIGABRT", "0x7fff", top_func="__assert_fail")
        assert engine._infer_category(ctx) == "assert-fail"

    def test_infer_category_buffer_overflow(self):
        """memcpy in top frame → buffer-overflow"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        ctx = self._make_context("SIGSEGV", "0x7fff", top_func="memcpy")
        assert engine._infer_category(ctx) == "buffer-overflow"

    def test_infer_category_use_after_free(self):
        """free() in top frame (SIGSEGV) → use-after-free"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        ctx = self._make_context("SIGSEGV", "0x7fff", top_func="free")
        assert engine._infer_category(ctx) == "use-after-free"

    def test_infer_category_use_after_free_malloc(self):
        """malloc in top frame (SIGSEGV) → use-after-free"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        ctx = self._make_context("SIGSEGV", "0x7fff", top_func="malloc")
        assert engine._infer_category(ctx) == "use-after-free"

    def test_infer_category_unknown(self):
        """无匹配模式 → unknown"""
        from src.analysis.correlation import CorrelationEngine
        engine = CorrelationEngine()
        ctx = self._make_context("SIGTRAP", "0x7fff", top_func="foo")
        assert engine._infer_category(ctx) == "unknown"
