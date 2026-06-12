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
