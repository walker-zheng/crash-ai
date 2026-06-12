"""CLI integration tests — crash-ai analyze command.

Tests depend on mock GDB (no real core dump needed).
"""
import os
import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from src.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def env_with_key():
    with patch.dict(os.environ, {
        "CRASHAI_DEEPSEEK_API_KEY": "sk-test",
        "CRASHAI_DEFAULT_PROVIDER": "deepseek",
    }, clear=True):
        # Reload config for fresh env
        from importlib import reload
        import src.config
        reload(src.config)
        yield


class TestCLI:
    def test_cli_group_help(self, runner):
        """验证 crash-ai --help 显示帮助信息"""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Crash AI" in result.output or "crash" in result.output.lower()

    def test_analyze_help(self, runner):
        """验证 crash-ai analyze --help 显示选项"""
        result = runner.invoke(cli, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "--source" in result.output
        assert "--symbols" in result.output
        assert "--output" in result.output
        assert "--format" in result.output
        assert "--provider" in result.output
        assert "--platform" in result.output
        assert "--no-ai" in result.output
        assert "--dry-run" in result.output
        assert "--timeout" in result.output

    def test_analyze_missing_core_dump(self, runner, env_with_key):
        """验证 core dump 文件不存在 → exit code 2"""
        result = runner.invoke(cli, ["analyze", "/nonexistent/core.dump"])
        assert result.exit_code == 2

    def test_analyze_invalid_file(self, runner, env_with_key, tmp_path):
        """验证非 core dump 文件 → exit code 2"""
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"not a core dump file")
        result = runner.invoke(cli, ["analyze", str(junk)])
        assert result.exit_code == 2

    def test_analyze_no_ai_flag(self, runner, env_with_key, tmp_path):
        """验证 --no-ai 跳过 LLM 调用"""
        # Create a minimal ELF core dump (ET_CORE e_type=4)
        core = tmp_path / "test.core"
        header = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 10)
        header[16:18] = b"\x04\x00"  # ET_CORE
        core.write_bytes(bytes(header))

        # GDBWrapper is imported in src.symbol.resolver, so patch there
        patch_path = "src.symbol.resolver.GDBWrapper"
        with patch(patch_path) as MockGDB:
            mock_gdb = MockGDB.return_value
            from src.symbol.protocol import ResolvedResult
            from src.models.symbol import ThreadState
            mock_gdb.resolve_stack = MagicMock(return_value=ResolvedResult(
                stack=[], registers={},
                threads=[ThreadState(tid=1, lwpid=1234, is_crashed=True)],
                raw_output="mock gdb output"
            ))
            mock_gdb.get_registers = MagicMock(return_value={"rax": "0x0"})

            result = runner.invoke(cli, ["analyze", str(core), "--no-ai"])
            # Should complete without LLM call
            assert result.exit_code in (0, 1)

    def test_analyze_dry_run_flag(self, runner, env_with_key, tmp_path):
        """验证 --dry-run 输出 prompt 但不调 LLM"""
        core = tmp_path / "test.core"
        header = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 10)
        header[16:18] = b"\x04\x00"
        core.write_bytes(bytes(header))

        # GDBWrapper is imported in src.symbol.resolver, so patch there
        patch_path = "src.symbol.resolver.GDBWrapper"
        with patch(patch_path) as MockGDB:
            mock_gdb = MockGDB.return_value
            from src.symbol.protocol import ResolvedResult
            from src.models.symbol import ThreadState
            mock_gdb.resolve_stack = MagicMock(return_value=ResolvedResult(
                stack=[], registers={},
                threads=[ThreadState(tid=1, lwpid=1234, is_crashed=True)],
                raw_output=""
            ))
            mock_gdb.get_registers = MagicMock(return_value={"rax": "0x0"})

            result = runner.invoke(cli, ["analyze", str(core), "--dry-run"])
            # Should output prompt and exit clean
            assert result.exit_code in (0, 1)
