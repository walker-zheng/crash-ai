"""Claude API 适配器 (Anthropic SDK)。"""
import json
import anthropic
from src.analysis.providers.base import LLMProvider


class AnthropicProvider(LLMProvider):
    """Claude API 适配器 — prompt 追加 JSON 输出指令。

    支持:
    - 标准模型 (TextBlock): 直接取 .text
    - Thinking 模型 (deepseek-v4-pro 等): 过滤 ThinkingBlock, 取 TextBlock.text
    """

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    async def chat_json(self, system: str, user: str, **kwargs) -> dict:
        """向 Claude/DeepSeek (Anthropic 兼容) 发送请求并解析 JSON 响应。"""
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
        text = self._extract_text(response.content)
        text = self._strip_markdown_fence(text)
        result = json.loads(text)

        # Normalize DeepSeek's flat CoT output into expected nested structure
        # Only trigger when response has CoT step keys but NOT the expected root_cause
        cot_keys = {"signal_analysis", "root_cause_inference", "evidence_extraction"}
        if "root_cause" not in result and cot_keys & set(result.keys()):
            result = self._normalize_response(result)

        return result

    @staticmethod
    def _normalize_response(data: dict) -> dict:
        """Normalize non-standard JSON responses into expected AnalysisReport format.

        DeepSeek with CoT prompts may output flat keys like:
        signal_analysis, root_cause_inference, evidence_extraction
        instead of the expected nested structure:
        root_cause: {category, description, crash_location, trigger_condition}
        evidence: [{type, description, relevance}]
        """
        normalized = {}

        # Map root_cause
        rc = {}
        if "root_cause_inference" in data:
            rc["description"] = str(data["root_cause_inference"])
        elif "signal_analysis" in data:
            rc["description"] = str(data["signal_analysis"])

        # Infer category from description or crash context
        desc_lower = rc.get("description", "").lower()
        if "null" in desc_lower or "null pointer" in desc_lower:
            rc["category"] = "null-deref"
        elif "double free" in desc_lower:
            rc["category"] = "double-free"
        elif "buffer overflow" in desc_lower or "stack overflow" in desc_lower:
            rc["category"] = "buffer-overflow"
        elif "use after free" in desc_lower or "uaf" in desc_lower:
            rc["category"] = "use-after-free"
        elif "race" in desc_lower:
            rc["category"] = "race-condition"
        elif "deadlock" in desc_lower:
            rc["category"] = "deadlock"
        elif "unaligned" in desc_lower:
            rc["category"] = "sigbus-unaligned"
        elif "divide" in desc_lower or "division" in desc_lower:
            rc["category"] = "division-by-zero"
        elif "assert" in desc_lower:
            rc["category"] = "assert-fail"
        else:
            rc["category"] = "unknown"

        rc["crash_location"] = data.get("stack_analysis", "") if isinstance(data.get("stack_analysis"), str) else ""
        rc["trigger_condition"] = ""
        normalized["root_cause"] = rc

        # Map evidence
        evidence = data.get("evidence_extraction", data.get("evidence", []))
        if isinstance(evidence, list):
            normalized["evidence"] = [
                {"type": "logic", "description": str(e), "relevance": "MEDIUM"}
                if isinstance(e, str) else e
                for e in evidence
            ]
        else:
            normalized["evidence"] = [
                {"type": "logic", "description": str(evidence), "relevance": "MEDIUM"}
            ]

        # Map fix_suggestion
        fix = data.get("fix_suggestion", "")
        if isinstance(fix, str):
            normalized["fix_suggestion"] = fix
        elif isinstance(fix, list):
            normalized["fix_suggestion"] = "\n".join(str(f) for f in fix)
        else:
            normalized["fix_suggestion"] = str(fix) if fix else ""

        # Map confidence
        normalized["confidence"] = float(data.get("confidence", 0.5))

        return normalized

    @staticmethod
    def _extract_text(content) -> str:
        """从响应 content 中提取文本。

        处理:
        - TextBlock: 直接返回 .text
        - ThinkingBlock (deepseek-v4-pro 等): 跳过, 取后续 TextBlock
        - 混合: 只返回第一个 TextBlock 的文本
        """
        for block in content:
            if hasattr(block, 'text'):
                return block.text
        # Fallback: try first block
        return str(content[0]) if content else ""

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
