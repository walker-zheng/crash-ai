"""LLM Router 单元测试 (with mocks — no real API calls)."""
import os
import pytest
from unittest.mock import patch, AsyncMock, MagicMock


@pytest.fixture
def config_with_keys():
    """Config 同时包含两个 API Key"""
    with patch.dict(os.environ, {
        "CRASHAI_DEEPSEEK_API_KEY": "sk-test-deepseek",
        "CRASHAI_ANTHROPIC_API_KEY": "sk-test-anthropic",
        "CRASHAI_DEFAULT_PROVIDER": "deepseek",
    }, clear=True):
        from importlib import reload
        import src.config
        reload(src.config)
        from src.config import Config
        return Config()


@pytest.fixture
def config_deepseek_only():
    """只有 DeepSeek Key"""
    with patch.dict(os.environ, {
        "CRASHAI_DEEPSEEK_API_KEY": "sk-test-deepseek",
        "CRASHAI_DEFAULT_PROVIDER": "deepseek",
    }, clear=True):
        from importlib import reload
        import src.config
        reload(src.config)
        from src.config import Config
        return Config()


class TestLLMRouter:
    def test_default_provider_from_config(self, config_with_keys):
        """验证从 Config.default_provider 选择 provider"""
        from src.analysis.llm_router import LLMRouter
        router = LLMRouter(config_with_keys)
        from src.analysis.providers.deepseek import DeepSeekProvider
        assert isinstance(router.provider, DeepSeekProvider)

    def test_explicit_provider_override(self, config_with_keys):
        """验证显式 provider 参数覆盖 Config"""
        from src.analysis.llm_router import LLMRouter
        router = LLMRouter(config_with_keys, provider="anthropic")
        from src.analysis.providers.anthropic import AnthropicProvider
        assert isinstance(router.provider, AnthropicProvider)

    def test_unsupported_provider_raises(self, config_with_keys):
        """验证不支持的 provider 名称抛出 ValueError"""
        from src.analysis.llm_router import LLMRouter
        with pytest.raises(ValueError, match="Unsupported provider"):
            LLMRouter(config_with_keys, provider="openai")


class TestAnthropicProvider:
    def test_strip_markdown_fence(self):
        """验证去除 markdown fence (```json ... ```)"""
        from src.analysis.providers.anthropic import AnthropicProvider
        result = AnthropicProvider._strip_markdown_fence(
            "```json\n{\"key\": \"value\"}\n```"
        )
        assert result == '{"key": "value"}'

    def test_strip_markdown_fence_no_wrapper(self):
        """验证无 fence 的文本保持不变"""
        from src.analysis.providers.anthropic import AnthropicProvider
        result = AnthropicProvider._strip_markdown_fence(
            '{"key": "value"}'
        )
        assert result == '{"key": "value"}'

    @pytest.mark.asyncio
    async def test_chat_json_calls_api(self):
        """验证 chat_json 调用 Anthropic API 并解析 JSON"""
        from src.analysis.providers.anthropic import AnthropicProvider
        provider = AnthropicProvider(api_key="sk-test")

        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = '{"result": "success"}'

        with patch.object(provider.client.messages, 'create', new_callable=AsyncMock, return_value=mock_response):
            result = await provider.chat_json("system", "user")
            assert result == {"result": "success"}


class TestDeepSeekProvider:
    @pytest.mark.asyncio
    async def test_chat_json_calls_api(self):
        """验证 chat_json 调用 DeepSeek API 并解析 JSON"""
        from src.analysis.providers.deepseek import DeepSeekProvider
        provider = DeepSeekProvider(api_key="sk-test")

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"result": "success"}'

        with patch.object(provider.client.chat.completions, 'create',
                          new_callable=AsyncMock, return_value=mock_response):
            result = await provider.chat_json("system", "user")
            assert result == {"result": "success"}
