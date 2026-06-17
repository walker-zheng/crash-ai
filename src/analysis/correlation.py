"""多源交叉验证 — 寄存器 × 堆栈 × 日志 一致性检查。"""
from typing import Dict, List, Optional

from src.models.analysis import CorrelatedContext, CrossValidation
from src.models.crash import CrashContext, MemRegion
from src.models.symbol import RawFrame


class CorrelationEngine:
    """多源交叉验证引擎。

    验证维度:
    1. 寄存器 × 堆栈一致性: 寄存器中的地址是否在某个帧中出现
    2. 寄存器 × 内存映射: 故障地址是否落在合法内存区域
    3. 堆栈 × 信号: 堆栈顶帧行为是否与信号类型一致
    4. 危险模式检测: 检测 double-free / use-after-free / NULL-deref 特征
    """

    def validate(self, ctx: CrashContext) -> CorrelatedContext:
        """执行多源交叉验证。"""
        validations: List[CrossValidation] = []

        # 1. Register × Stack consistency
        validations.extend(
            self._check_register_stack_consistency(ctx.registers, ctx.raw_stack)
        )

        # 2. Fault address × Memory maps
        validations.extend(
            self._check_fault_addr_memory(ctx.fault_addr, ctx.memory_maps)
        )

        # 3. Stack × Signal consistency
        validations.extend(
            self._check_stack_signal_consistency(ctx.raw_stack, ctx.signal)
        )

        # 4. Danger pattern detection
        danger_patterns = self._detect_danger_patterns(ctx)

        # 5. Build register → var map (heuristic)
        register_var_map = self._build_register_var_map(ctx.registers)

        # 6. Infer crash category from deterministic context analysis
        suggested_category = self._infer_category(ctx)

        return CorrelatedContext(
            timeline_alignment=[
                {"source_a": v.source_a, "source_b": v.source_b,
                 "consensus": v.consensus}
                for v in validations
            ],
            register_var_map=register_var_map,
            memory_analysis=self._memory_analysis(ctx.fault_addr, ctx.memory_maps),
            danger_patterns=danger_patterns,
            suggested_category=suggested_category,
        )

    def _check_register_stack_consistency(
        self, registers: Dict[str, str], frames: List[RawFrame]
    ) -> List[CrossValidation]:
        """检查寄存器值与堆栈帧地址的一致性"""
        results: List[CrossValidation] = []
        frame_addrs = {f.address for f in frames}

        for reg_name, reg_val in registers.items():
            if reg_val in frame_addrs:
                results.append(CrossValidation(
                    source_a=f"register:{reg_name}",
                    source_b="stack",
                    consensus=f"{reg_name}={reg_val} found in stack frame",
                ))
        return results

    def _check_fault_addr_memory(
        self, fault_addr: str, memory_maps: List[MemRegion]
    ) -> List[CrossValidation]:
        """检查故障地址是否落入内存映射区域"""
        results: List[CrossValidation] = []
        try:
            addr_int = int(fault_addr, 16)
        except (ValueError, TypeError):
            return results

        in_any_region = False
        for region in memory_maps:
            try:
                start = int(region.start_addr, 16)
                end = int(region.end_addr, 16)
                if start <= addr_int < end:
                    in_any_region = True
                    results.append(CrossValidation(
                        source_a="fault_addr",
                        source_b="memory_maps",
                        consensus=f"fault_addr {fault_addr} in {region.mapped_file} ({region.permissions})",
                    ))
            except (ValueError, TypeError):
                continue

        if not in_any_region and memory_maps:
            results.append(CrossValidation(
                source_a="fault_addr",
                source_b="memory_maps",
                consensus=f"fault_addr {fault_addr} not in any mapped region",
                contradiction="Access to unmapped memory",
            ))

        return results

    def _check_stack_signal_consistency(
        self, frames: List[RawFrame], signal: str
    ) -> List[CrossValidation]:
        """检查堆栈顶部帧与信号类型的一致性"""
        results: List[CrossValidation] = []
        if not frames:
            return results

        top_func = frames[0].function.lower() if frames[0].function else ""

        signal_patterns = {
            "SIGSEGV": ["null", "deref", "memcpy", "memset", "strcpy", "strcat", "memmove"],
            "SIGABRT": ["abort", "assert", "__assert_fail"],
            "SIGFPE": ["div", "mod", "fpu"],
            "SIGBUS": ["mmap", "align"],
        }

        expected = signal_patterns.get(signal, [])
        if expected and not any(pat in top_func for pat in expected):
            results.append(CrossValidation(
                source_a="stack_top",
                source_b="signal",
                consensus=f"Top function '{frames[0].function}' not typical for {signal}",
                contradiction=f"Unusual crash pattern for {signal}",
            ))

        return results

    def _detect_danger_patterns(self, ctx: CrashContext) -> List[str]:
        """检测常见危险模式"""
        patterns: List[str] = []

        # NULL deref
        if ctx.fault_addr == "0x0" or ctx.fault_addr == "0x0000000000000000":
            patterns.append("NULL pointer dereference")
        if "0x0" in ctx.registers.values():
            patterns.append("NULL register value detected")

        # Rip = 0x0
        if ctx.registers.get("rip", "") in ("0x0", "0x0000000000000000"):
            patterns.append("instruction pointer is NULL (rip=0x0)")

        # Stack top check
        if ctx.raw_stack:
            top = ctx.raw_stack[0].function
            if top:
                top_lower = top.lower()
                if "free" in top_lower:
                    patterns.append("potential double-free (free() in crash frame)")
                elif "memcpy" in top_lower or "sprintf" in top_lower or "strcpy" in top_lower:
                    patterns.append("potential buffer overflow (string/memory copy in crash frame)")
                elif "malloc" in top_lower or "new" in top_lower:
                    patterns.append("potential use-after-free or allocation failure")

        # SIGSEGV specific
        if ctx.signal == "SIGSEGV" and ctx.fault_addr == "0x0":
            patterns.append("SIGSEGV with fault_addr=0x0: classic NULL dereference")

        return patterns

    def _infer_category(self, ctx: CrashContext) -> str:
        """Infer the most likely crash category from deterministic context analysis.

        Uses signal, fault address, register state, and stack top function
        to determine the category without relying on LLM or keyword matching.
        Replaces the old hardcoded keyword-mapping approach in _normalize_response().
        """
        fault_addr = ctx.fault_addr or ""
        signal = ctx.signal or ""
        reg_values = list(ctx.registers.values()) if ctx.registers else []

        # NULL pointer dereference — fault at address 0
        if fault_addr in ("0x0", "0x0000000000000000"):
            return "null-deref"

        # Look at top stack frame function
        top_func = ""
        if ctx.raw_stack and ctx.raw_stack[0] and ctx.raw_stack[0].function:
            top_func = ctx.raw_stack[0].function.lower()

        # SIGBUS — unaligned access / bad address
        if signal == "SIGBUS":
            return "sigbus-unaligned"

        # SIGFPE — arithmetic error (division by zero, etc.)
        if signal == "SIGFPE":
            return "division-by-zero"

        # SIGABRT — assertion failure or detected corruption (e.g. double-free)
        if signal == "SIGABRT":
            if top_func and ("free" in top_func or "delete" in top_func):
                return "double-free"
            return "assert-fail"

        # Check top frame function for known crash operation patterns
        if top_func:
            if any(fn in top_func for fn in
                   ["memcpy", "memmove", "strcpy", "strcat", "sprintf", "snprintf", "bcopy"]):
                return "buffer-overflow"
            if "free" in top_func or "realloc" in top_func:
                return "use-after-free"
            if any(fn in top_func for fn in ["malloc", "calloc", "new"]):
                return "use-after-free"

        # SIGSEGV — further analyze register values for indirect NULL deref
        if signal == "SIGSEGV":
            if any(v in ("0x0", "0x0000000000000000") for v in reg_values):
                return "null-deref"
            return "null-deref"  # common default for SIGSEGV

        # Check if any register is NULL as a general safety net
        if any(v in ("0x0", "0x0000000000000000") for v in reg_values):
            return "null-deref"

        return "unknown"

    def _build_register_var_map(self, registers: Dict[str, str]) -> dict:
        """构建寄存器 → 值映射摘要"""
        return {
            reg: {"value": val, "is_null": val in ("0x0", "0x0000000000000000")}
            for reg, val in registers.items()
        }

    def _memory_analysis(self, fault_addr: str, memory_maps: List[MemRegion]) -> Optional[str]:
        """分析故障地址所在的内存区域属性"""
        if not fault_addr or not memory_maps:
            return None
        try:
            addr_int = int(fault_addr, 16)
        except (ValueError, TypeError):
            return None

        for region in memory_maps:
            try:
                start = int(region.start_addr, 16)
                end = int(region.end_addr, 16)
                if start <= addr_int < end:
                    if "w" not in region.permissions:
                        return f"Write to read-only memory ({region.permissions}) at {region.mapped_file}"
                    if "x" in region.permissions:
                        return f"Executing data in executable region {region.mapped_file} — possible code injection"
                    return f"Address in {region.mapped_file} ({region.permissions})"
            except (ValueError, TypeError):
                continue
        return f"Address {fault_addr} not in any mapped region — access to unmapped/invalid memory"
