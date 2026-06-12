"""Claude API 适配器 (Anthropic SDK)。"""
import json
import anthropic
from src.analysis.providers.base import LLMProvider


class AnthropicProvider(LLMProvider):
    """Claude API 适配器 — prompt 追加 JSON 输出指令。"""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    async def chat_json(self, system: str, user: str, **kwargs) -> dict:
        """向 Claude 发送请求并解析 JSON 响应。"""
        enhanced_user = (
            f"{user}\n\n"
            "Return ONLY valid JSON, no markdown fences, no extra text."
        )
        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": enhanced_user}],
            **kwargs
        )
        text = response.content[0].text
        text = self._strip_markdown_fence(text)
        return json.loads(text)

    @staticmethod
    def _strip_markdown_fence(text: str) -> str:
        """移除可能的 markdown 代码块包装。"""
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            if lines[-1].strip() == "```":
                text = "\n".join(lines[1:-1])
            else:
                text = "\n".join(lines[1:])
        return text
