"""LLM Provider 抽象基类。"""
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """LLM Provider 抽象基类。

    各 provider 自行封装 JSON 输出强制逻辑:
    - Claude: prompt 追加 "Return ONLY valid JSON, no markdown fences"
    - DeepSeek (OpenAI 兼容): response_format={"type": "json_object"}
    """

    @abstractmethod
    async def chat_json(self, system: str, user: str, **kwargs) -> dict:
        """发送 chat 请求并返回解析后的 JSON dict。"""
        ...
