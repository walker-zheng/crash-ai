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

    # ------------------------------------------------------------------
    # _normalize_response 测试
    # ------------------------------------------------------------------

    def test_normalize_cot_flat_to_nested(self):
        """CoT 扁平输出 → 转为嵌套 AnalysisReport 结构"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {"typical_cause": "null pointer crash"},
            "root_cause_inference": {"trigger": "dereferenced NULL pointer"},
            "evidence_extraction": ["rax is 0x0", "fault at 0x0"],
        }
        result = AnthropicProvider._normalize_response(raw)
        assert "root_cause" in result
        assert "category" in result["root_cause"]
        assert "description" in result["root_cause"]
        assert "evidence" in result
        assert len(result["evidence"]) == 2

    def test_normalize_explicit_category_trusted(self):
        """Level 1: LLM 显式 category 直接使用"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {},
            "root_cause_inference": {"category": "null-deref", "trigger": "oops"},
            "evidence_extraction": [],
        }
        result = AnthropicProvider._normalize_response(raw)
        assert result["root_cause"]["category"] == "null-deref"

    def test_normalize_explicit_category_normalized(self):
        """Level 1: LLM 显式 category 经 _match_category_keyword 归一化为规范形式"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {},
            "root_cause_inference": {"category": "Null pointer dereference", "trigger": "oops"},
            "evidence_extraction": [],
        }
        result = AnthropicProvider._normalize_response(raw)
        assert result["root_cause"]["category"] == "null-deref", \
            f"Expected null-deref, got {result['root_cause']['category']}"

    def test_normalize_explicit_category_fallback_to_raw(self):
        """Level 1: 无法识别的 category 保留原始值"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {},
            "root_cause_inference": {"category": "type-confusion", "trigger": "oops"},
            "evidence_extraction": [],
        }
        result = AnthropicProvider._normalize_response(raw)
        assert result["root_cause"]["category"] == "type-confusion"

    def test_normalize_suggested_category_used(self):
        """Level 2: 无 LLM 显式 category → 使用 CorrelationEngine suggested_category"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {},
            "root_cause_inference": {"trigger": "dereferenced NULL pointer"},
            "evidence_extraction": [],
        }
        result = AnthropicProvider._normalize_response(raw, suggested_category="null-deref")
        assert result["root_cause"]["category"] == "null-deref"

    def test_normalize_suggested_category_overrides_description_keyword(self):
        """Level 2 > Level 3: suggested_category 优先于描述文本关键词"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {"typical_cause": "double free detected"},
            "root_cause_inference": {"trigger": "some crash but actually assert"},
            "evidence_extraction": [],
        }
        # 描述文本包含 "free" 关键字 → 如果不传 suggested_category 会匹配为 "double-free"
        # 但 suggested_category="assert-fail" 应优先
        result = AnthropicProvider._normalize_response(raw, suggested_category="assert-fail")
        assert result["root_cause"]["category"] == "assert-fail", \
            f"Expected assert-fail, got {result['root_cause']['category']}"

    def test_normalize_fallback_to_keyword_matching(self):
        """Level 3: 无 LLM category + 无 suggested_category → 描述文本关键词匹配"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {"typical_cause": "double free of memory block"},
            "root_cause_inference": {"trigger": "double free detected"},
            "evidence_extraction": [],
        }
        result = AnthropicProvider._normalize_response(raw)
        assert result["root_cause"]["category"] == "double-free"

    def test_normalize_fallback_dash_conversion(self):
        """Level 3: 无关键词匹配 → space-to-dash 转换"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {"typical_cause": "something weird happened"},
            "root_cause_inference": {"trigger": "weird crash"},
            "evidence_extraction": [],
        }
        result = AnthropicProvider._normalize_response(raw)
        # _match_category_keyword fallback: "weird-crash"
        assert result["root_cause"]["category"] == "weird-crash"

    def test_normalize_evidence_string_list(self):
        """evidence_extraction 字符串列表 → evidence dict 列表"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {},
            "root_cause_inference": {"trigger": "test"},
            "evidence_extraction": ["rax=0x0", "rip in foo"],
        }
        result = AnthropicProvider._normalize_response(raw)
        assert len(result["evidence"]) == 2
        for ev in result["evidence"]:
            assert "type" in ev
            assert "description" in ev
            assert "relevance" in ev

    def test_normalize_evidence_single_string(self):
        """evidence_extraction 单字符串 → 包装为 list"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {},
            "root_cause_inference": {"trigger": "test"},
            "evidence_extraction": "single evidence string",
        }
        result = AnthropicProvider._normalize_response(raw)
        assert len(result["evidence"]) == 1
        assert result["evidence"][0]["description"] == "single evidence string"

    def test_normalize_fix_suggestion_list(self):
        """fix_suggestion 列表 → 换行拼接"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {},
            "root_cause_inference": {"trigger": "test"},
            "evidence_extraction": [],
            "fix_suggestion": ["fix 1", "fix 2"],
        }
        result = AnthropicProvider._normalize_response(raw)
        assert "fix 1\nfix 2" in result["fix_suggestion"]

    def test_normalize_confidence_default(self):
        """confidence 缺失 → 默认 0.5"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {},
            "root_cause_inference": {"trigger": "test"},
            "evidence_extraction": [],
        }
        result = AnthropicProvider._normalize_response(raw)
        assert result["confidence"] == 0.5

    def test_normalize_crash_location_from_stack_analysis(self):
        """crash_location 从 stack_analysis 提取"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {},
            "root_cause_inference": {"trigger": "test"},
            "evidence_extraction": [],
            "stack_analysis": "foo.c:42",
        }
        result = AnthropicProvider._normalize_response(raw)
        assert "foo.c:42" in result["root_cause"]["crash_location"]

    def test_normalize_trigger_condition_null_in_register(self):
        """trigger_condition 识别 NULL 指针"""
        from src.analysis.providers.anthropic import AnthropicProvider
        raw = {
            "signal_analysis": {},
            "root_cause_inference": {"trigger": "test"},
            "evidence_extraction": [],
            "register_analysis": "null pointer in rax",
        }
        result = AnthropicProvider._normalize_response(raw)
        assert "NULL" in result["root_cause"]["trigger_condition"]

    def test_normalize_minimal_input(self):
        """最小输入不抛异常"""
        from src.analysis.providers.anthropic import AnthropicProvider
        result = AnthropicProvider._normalize_response({})
        assert "root_cause" in result
        assert "evidence" in result
        assert isinstance(result["evidence"], list)
        assert result["fix_suggestion"] == ""
        assert result["confidence"] == 0.5


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
