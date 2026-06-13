"""Claude API 适配器 (Anthropic SDK)。"""
import json
import re
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

        # Map root_cause — handle both flat strings and nested dicts
        rc = {}
        rci = data.get("root_cause_inference", {})
        sig = data.get("signal_analysis", {})

        # Extract description
        if isinstance(rci, dict):
            rc["description"] = rci.get("trigger", str(rci))
        elif isinstance(rci, str):
            rc["description"] = rci
        elif isinstance(sig, dict):
            rc["description"] = sig.get("typical_cause", sig.get("meaning", str(sig)))
        elif isinstance(sig, str):
            rc["description"] = sig

        # Extract category (prefer explicit category from LLM)
        if isinstance(rci, dict) and "category" in rci:
            raw_cat = rci["category"].lower()
            if "null" in raw_cat:
                rc["category"] = "null-deref"
            elif "double free" in raw_cat:
                rc["category"] = "double-free"
            elif "buffer" in raw_cat or "overflow" in raw_cat:
                rc["category"] = "buffer-overflow"
            elif "use after free" in raw_cat or "uaf" in raw_cat:
                rc["category"] = "use-after-free"
            elif "race" in raw_cat:
                rc["category"] = "race-condition"
            elif "deadlock" in raw_cat:
                rc["category"] = "deadlock"
            elif "unaligned" in raw_cat:
                rc["category"] = "sigbus-unaligned"
            elif "divide" in raw_cat or "division" in raw_cat:
                rc["category"] = "division-by-zero"
            elif "assert" in raw_cat:
                rc["category"] = "assert-fail"
            else:
                rc["category"] = raw_cat.replace(" ", "-")[:40]
        else:
            # Infer from description text
            desc_lower = rc.get("description", "").lower()
            if "null" in desc_lower:
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
            elif "divide" in desc_lower:
                rc["category"] = "division-by-zero"
            elif "assert" in desc_lower:
                rc["category"] = "assert-fail"
            else:
                rc["category"] = "unknown"

        rc["crash_location"] = _extract_crash_location(data)
        rc["trigger_condition"] = _extract_trigger_condition(data)
        normalized["root_cause"] = rc

        # Map evidence
        evidence = data.get("evidence_extraction", data.get("evidence", []))
        if isinstance(evidence, list):
            normalized["evidence"] = [
                {"type": "logic", "description": str(e), "relevance": "MEDIUM"}
                if isinstance(e, str) else e
                for e in evidence
            ]
        elif evidence:
            normalized["evidence"] = [
                {"type": "logic", "description": str(evidence), "relevance": "MEDIUM"}
            ]

        # Map fix_suggestion
        fix = data.get("fix_suggestion", "")
        if isinstance(fix, str):
            normalized["fix_suggestion"] = fix
        elif isinstance(fix, list):
            normalized["fix_suggestion"] = "\n".join(str(f) for f in fix)
        elif fix:
            normalized["fix_suggestion"] = str(fix)

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


# ---------------------------------------------------------------------------
# Module-level helpers for response normalization
# ---------------------------------------------------------------------------

def _extract_crash_location(data: dict) -> str:
    """Extract crash location from CoT analysis fields."""
    stack = data.get("stack_analysis", "")
    # Handle nested dict format: {"frames": [{...}], "crash_path": "..."}
    if isinstance(stack, dict):
        frames = stack.get("frames", [])
        if frames and isinstance(frames[0], dict):
            f = frames[0]
            func = f.get("function", "")
            addr = f.get("address", "")
            mod = f.get("module", "")
            return f"{func} ({mod} @ {addr})"
        return stack.get("crash_path", "")[:120]
    if isinstance(stack, str) and stack:
        m = re.search(r'(\w+\.\w+):(\d+)', stack)
        if m:
            return f"{m.group(1)}:{m.group(2)}"
        return stack.split("\n")[0][:120]
    return ""


def _extract_trigger_condition(data: dict) -> str:
    """Extract trigger condition from CoT analysis fields."""
    reg = data.get("register_analysis", "")
    if isinstance(reg, str) and reg:
        if "null" in reg.lower() or "0x0" in reg:
            return "Dereference of NULL or invalid pointer"
        return reg[:200]
    return ""
