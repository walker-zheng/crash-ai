"""Tests for SymbolResolver and package extractors."""
import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock
from src.models.crash import CrashContext, CrashMetadata
from src.models.symbol import ThreadState, ResolvedCrashContext


@pytest.fixture
def sample_crash_ctx():
    meta = CrashMetadata(
        timestamp=datetime.now(), hostname="test", kernel_version="5.15",
        distribution="ubuntu", arch="x86_64", coredump_size_bytes=1024,
    )
    return CrashContext(
        signal="SIGSEGV", fault_addr="0x0",
        thread_states=[], registers={}, raw_stack=[],
        memory_maps=[], loaded_modules=[], metadata=meta,
    )


class TestSymbolResolver:
    def test_init_defaults_to_gdb(self):
        """验证默认使用 GDBWrapper"""
        from src.symbol.resolver import SymbolResolver
        from src.symbol.gdb_wrapper import GDBWrapper
        with patch('src.symbol.gdb_wrapper.shutil.which', return_value="/usr/bin/gdb"):
            resolver = SymbolResolver()
        assert isinstance(resolver.debugger, GDBWrapper)

    def test_accepts_custom_debugger(self):
        """验证接受自定义 debugger"""
        from src.symbol.resolver import SymbolResolver
        from src.symbol.lldb_wrapper import LLDBWrapper
        with patch('src.symbol.gdb_wrapper.shutil.which', return_value="/usr/bin/gdb"):
            resolver = SymbolResolver(debugger=LLDBWrapper())
        assert isinstance(resolver.debugger, LLDBWrapper)

    def test_resolve_without_symbols(self, sample_crash_ctx):
        """验证无符号目录时仍能生成 ResolvedCrashContext（降级）"""
        from src.symbol.resolver import SymbolResolver
        from src.symbol.protocol import ResolvedResult
        with patch('src.symbol.gdb_wrapper.shutil.which', return_value="/usr/bin/gdb"):
            resolver = SymbolResolver()

        mock_result = ResolvedResult(
            stack=[], registers={}, threads=[
                ThreadState(tid=1, lwpid=1234, is_crashed=True)
            ], raw_output="mock gdb output"
        )
        with patch.object(resolver.debugger, 'resolve_stack', return_value=mock_result):
            result = resolver.resolve(
                core_path=Path("/tmp/test.core"),
                crash_ctx=sample_crash_ctx,
            )
            assert isinstance(result, ResolvedCrashContext)
            assert result.crash_thread.is_crashed

    def test_resolve_transfers_metadata(self, sample_crash_ctx):
        """验证 metadata/memory_maps/loaded_modules 透传"""
        from src.symbol.resolver import SymbolResolver
        from src.symbol.protocol import ResolvedResult
        with patch('src.symbol.gdb_wrapper.shutil.which', return_value="/usr/bin/gdb"):
            resolver = SymbolResolver()

        mock_result = ResolvedResult(
            stack=[], registers={}, threads=[
                ThreadState(tid=1, lwpid=1234, is_crashed=True)
            ], raw_output=""
        )
        with patch.object(resolver.debugger, 'resolve_stack', return_value=mock_result):
            result = resolver.resolve(
                core_path=Path("/tmp/test.core"),
                crash_ctx=sample_crash_ctx,
            )
            assert result.metadata == sample_crash_ctx.metadata
            assert result.memory_maps == sample_crash_ctx.memory_maps
            assert result.loaded_modules == sample_crash_ctx.loaded_modules


class TestPackageExtractors:
    def test_rpm_extractor_stub(self):
        """验证 RPM extractor 可导入"""
        from src.symbol.rpm_extractor import extract_rpm_symbols
        assert callable(extract_rpm_symbols)

    def test_deb_extractor_stub(self):
        """验证 DEB extractor 可导入"""
        from src.symbol.deb_extractor import extract_deb_symbols
        assert callable(extract_deb_symbols)

    def test_dsym_extractor_stub(self):
        """验证 dSYM extractor 可导入"""
        from src.symbol.dsym_extractor import extract_dsym_symbols
        assert callable(extract_dsym_symbols)
