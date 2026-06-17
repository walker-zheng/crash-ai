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
        self.client = anthropic.AsyncAnthropic(api_key=api_key)
        self.model = model

    async def chat_json(self, system: str, user: str, **kwargs) -> dict:
        """向 Claude/DeepSeek (Anthropic 兼容) 发送请求并解析 JSON 响应。

        Args:
            system: System prompt.
            user: User prompt.
            **kwargs: Extra keyword arguments. Supports 'danger_patterns' (list[str])
                passed from the AnalysisEngine for category inference during normalization.
        """
        # Extract danger_patterns and suggested_category before forwarding remaining kwargs
        danger_patterns = kwargs.pop("danger_patterns", None)
        suggested_category = kwargs.pop("suggested_category", "")

        enhanced_user = (
            f"{user}\n\n"
            "Return ONLY valid JSON, no markdown fences, no extra text."
        )
        response = await self.client.messages.create(
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
            result = self._normalize_response(result, danger_patterns=danger_patterns,
                                               suggested_category=suggested_category)

        return result


    @staticmethod
    def _normalize_response(data: dict, danger_patterns: list[str] | None = None,
                            suggested_category: str = "") -> dict:
        """Normalize non-standard JSON responses into expected AnalysisReport format.

        DeepSeek with CoT prompts may output flat keys like:
        signal_analysis, root_cause_inference, evidence_extraction
        instead of the expected nested structure:
        root_cause: {category, description, crash_location, trigger_condition}
        evidence: [{type, description, relevance}]

        Category inference priority (3 levels):
          1. LLM explicit category (most trustworthy — used as-is)
          2. CorrelationEngine deterministic category (from _infer_category ctx analysis)
          3. LLM description keyword matching (fallback)

        Args:
            data: Raw LLM response dict.
            danger_patterns: Optional CorrelationEngine danger patterns (kept for
                compatibility, no longer used for category inference).
            suggested_category: CorrelationEngine's deterministic category guess
                from _infer_category(), based on signal/fault_addr/registers/stack.
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

        # Extract category — 三层优先级:
        #   1. LLM 显式 category (最可信, 直接信任)
        #   2. CorrelationEngine 确定性推断 (多源交叉验证)
        #   3. LLM 描述文本关键词匹配 (后备)
        explicit_cat = None
        if isinstance(rci, dict) and "category" in rci:
            raw = rci["category"].strip()
            explicit_cat = raw if raw else None

        if explicit_cat:
            rc["category"] = explicit_cat
        elif suggested_category:
            # 使用 CorrelationEngine 的多源交叉验证结果 (确定性分析)
            rc["category"] = suggested_category
        else:
            # 后备: 从 LLM 描述文本关键词匹配
            desc_lower = rc.get("description", "").lower()
            rc["category"] = AnthropicProvider._match_category_keyword(desc_lower) or "unknown"

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
    def _match_category_keyword(text: str) -> str | None:
        """Map a text string to a crash category using keyword matching.

        This is the single source of truth for keyword → category mapping,
        used both for LLM's explicit category field and for description-based fallback.
        """
        if not text:
            return None
        # Order matters: more specific patterns must come first
        if "null" in text:
            return "null-deref"
        if "double free" in text:
            return "double-free"
        if "use after free" in text or " uaf " in text or text.startswith("uaf"):
            return "use-after-free"
        if "buffer overflow" in text or "stack overflow" in text:
            return "buffer-overflow"
        if "buffer" in text or "overflow" in text:
            return "buffer-overflow"
        if "race" in text:
            return "race-condition"
        if "deadlock" in text:
            return "deadlock"
        if "unaligned" in text:
            return "sigbus-unaligned"
        if "divide" in text or "division" in text:
            return "division-by-zero"
        if "assert" in text:
            return "assert-fail"
        # Return text with spaces replaced as fallback
        cleaned = text.replace(" ", "-")[:40]
        return cleaned if cleaned else None

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
