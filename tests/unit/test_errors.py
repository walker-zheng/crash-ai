"""Crash AI 异常层级单元测试。"""
import pytest
from src.errors import (
    CrashAIError, InputError, ConfigError,
    NetworkError, AnalysisIncompleteError
)


class TestExceptions:
    def test_input_error_exit_code(self):
        """InputError.exit_code == 2"""
        assert InputError("test").exit_code == 2

    def test_config_error_exit_code(self):
        """ConfigError.exit_code == 3"""
        assert ConfigError("test").exit_code == 3

    def test_network_error_exit_code(self):
        """NetworkError.exit_code == 4"""
        assert NetworkError("test").exit_code == 4

    def test_analysis_incomplete_exit_code(self):
        """AnalysisIncompleteError.exit_code == 1"""
        assert AnalysisIncompleteError("test").exit_code == 1

    def test_base_error_exit_code(self):
        """CrashAIError.exit_code == 5"""
        assert CrashAIError("test").exit_code == 5

    def test_all_errors_inherit_base(self):
        """所有异常继承 CrashAIError"""
        assert issubclass(InputError, CrashAIError)
        assert issubclass(ConfigError, CrashAIError)
        assert issubclass(NetworkError, CrashAIError)
        assert issubclass(AnalysisIncompleteError, CrashAIError)

    def test_error_message_preserved(self):
        """异常消息正确保留"""
        e = InputError("core dump corrupted: bad magic")
        assert "core dump corrupted" in str(e)

    def test_network_error_with_url(self):
        """网络错误可以携带 URL 信息"""
        e = NetworkError("Connection timeout: https://api.deepseek.com")
        assert "Connection timeout" in str(e)
        assert "api.deepseek.com" in str(e)

    def test_analysis_incomplete_with_details(self):
        """分析不完整携带详细信息"""
        e = AnalysisIncompleteError(
            "LLM returned invalid JSON after 3 retries"
        )
        assert "3 retries" in str(e)


class TestErrorInContext:
    """验证异常在实际使用场景中的行为"""

    def test_input_error_for_invalid_format(self):
        """模拟 format_detector 场景"""
        from src.input.format_detector import detect_format
        import tempfile
        from pathlib import Path

        tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        tmp.write(b"not valid\x00\x00\x00\x00")
        tmp_path = Path(tmp.name)
        tmp.close()

        try:
            with pytest.raises(InputError) as exc_info:
                detect_format(tmp_path)
            assert exc_info.value.exit_code == 2
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_config_error_for_missing_key(self):
        """模拟缺少 API Key 场景"""
        from src.analysis.llm_router import LLMRouter
        from src.config import Config
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {}, clear=True):
            from importlib import reload
            import src.config
            reload(src.config)
            from src.config import Config

            config = Config()
            with pytest.raises(ValueError, match="not set|Unsupported"):
                LLMRouter(config, provider="anthropic")
