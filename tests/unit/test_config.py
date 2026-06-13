import os
import pytest
from unittest.mock import patch


class TestConfig:
    def test_load_from_env_vars(self):
        """验证从环境变量加载所有配置项"""
        env_vars = {
            "CRASHAI_DEEPSEEK_API_KEY": "sk-test-deepseek",
            "CRASHAI_ANTHROPIC_API_KEY": "sk-test-anthropic",
            "CRASHAI_DEFAULT_PROVIDER": "anthropic",
            "CRASHAI_CACHE_DIR": "/tmp/crash-ai-test",
            "CRASHAI_TIMEOUT": "60",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            from importlib import reload
            import src.config
            reload(src.config)
            from src.config import Config
            c = Config()
            assert c.deepseek_api_key == "sk-test-deepseek"
            assert c.anthropic_api_key == "sk-test-anthropic"
            assert c.default_provider == "anthropic"
            assert c.cache_dir == "/tmp/crash-ai-test"
            assert c.timeout == 60

    def test_default_provider_fallback(self):
        """验证 CRASHAI_DEFAULT_PROVIDER 默认值为 deepseek"""
        with patch.dict(os.environ, {}, clear=True):
            from importlib import reload
            import src.config
            reload(src.config)
            from src.config import Config
            c = Config()
            assert c.default_provider == "deepseek"

    def test_timeout_default_30(self):
        """验证 CRASHAI_TIMEOUT 默认值为 30"""
        with patch.dict(os.environ, {}, clear=True):
            from importlib import reload
            import src.config
            reload(src.config)
            from src.config import Config
            c = Config()
            assert c.timeout == 30

    def test_missing_api_keys_allowed(self):
        """验证缺少 API Key 不崩溃 (至少一个即可, 运行时检查)"""
        with patch.dict(os.environ, {}, clear=True):
            from importlib import reload
            import src.config
            reload(src.config)
            from src.config import Config
            c = Config()
            assert c.deepseek_api_key == ""
            assert c.anthropic_api_key == ""

    def test_cache_dir_expands_tilde(self):
        """验证 CRASHAI_CACHE_DIR 中的 ~ 展开为 $HOME"""
        with patch.dict(os.environ, {"CRASHAI_CACHE_DIR": "~/.cache/crash-ai"}, clear=True):
            from importlib import reload
            import src.config
            reload(src.config)
            from src.config import Config
            c = Config()
            assert c.cache_dir.startswith("/")  # ~ expanded
            assert ".cache/crash-ai" in c.cache_dir
