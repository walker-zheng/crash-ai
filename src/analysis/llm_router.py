"""LLM Provider 路由器。"""
from src.analysis.providers.base import LLMProvider
from src.analysis.providers.anthropic import AnthropicProvider
from src.analysis.providers.deepseek import DeepSeekProvider


class LLMRouter:
    """LLM Provider 路由器。"""

    PROVIDERS = {
        "anthropic": AnthropicProvider,
        "deepseek": DeepSeekProvider,
    }

    def __init__(self, config, provider: str | None = None):
        """初始化路由器。

        Args:
            config: Config 实例
            provider: 显式 provider 名称 (覆盖 Config.default_provider)
        """
        self.config = config
        provider_name = provider or config.default_provider
        self.provider = self._init_provider(provider_name)

    def _init_provider(self, name: str) -> LLMProvider:
        """根据名称初始化 provider 实例。"""
        provider_cls = self.PROVIDERS.get(name)
        if provider_cls is None:
            raise ValueError(
                f"Unsupported provider: {name}. "
                f"Available: {', '.join(self.PROVIDERS.keys())}"
            )
        if name == "anthropic":
            if not self.config.anthropic_api_key:
                raise ValueError("CRASHAI_ANTHROPIC_API_KEY is not set")
            return provider_cls(api_key=self.config.anthropic_api_key)
        elif name == "deepseek":
            if not self.config.deepseek_api_key:
                raise ValueError("CRASHAI_DEEPSEEK_API_KEY is not set")
            return provider_cls(api_key=self.config.deepseek_api_key)
        raise ValueError(f"Unknown provider: {name}")

    async def analyze(self, system: str, user: str) -> dict:
        """通过当前 provider 执行 LLM 分析。"""
        return await self.provider.chat_json(system, user)
