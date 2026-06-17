"""DeepSeek API 适配器 (OpenAI 兼容接口)。"""
import json
from openai import AsyncOpenAI
from src.analysis.providers.base import LLMProvider


class DeepSeekProvider(LLMProvider):
    """DeepSeek API 适配器 — response_format={"type": "json_object"}。"""

    def __init__(self, api_key: str, model: str = "deepseek-chat"):
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com"
        )
        self.model = model

    async def chat_json(self, system: str, user: str, **kwargs) -> dict:
        """向 DeepSeek 发送请求并解析 JSON 响应。

        Pops CorrelationEngine-specific kwargs (danger_patterns, suggested_category)
        before forwarding to OpenAI SDK to avoid unrecognized parameter errors.
        """
        # Pop correlation-only kwargs that are not OpenAI API parameters
        kwargs.pop("danger_patterns", None)
        kwargs.pop("suggested_category", "")
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            response_format={"type": "json_object"},
            **kwargs
        )
        return json.loads(response.choices[0].message.content)
