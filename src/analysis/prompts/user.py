"""User prompt 构建函数 — 将 ResolvedCrashContext 序列化为 LLM 输入。"""
from src.models.symbol import ResolvedCrashContext


def build_user_prompt(ctx: ResolvedCrashContext, correlations: list = None) -> str:
    """构建发送给 LLM 的 user prompt。

    包含:
    - 崩溃概览 (信号、架构、内核、发行版、core 大小)
    - 崩溃位置摘要 (函数、文件、行号 — 从顶帧提取)
    - 崩溃线程堆栈回溯 (最多50帧, 崩溃帧用 → 标记)
    - 寄存器快照
    - 交叉验证提示 (可选, 来自 CorrelationEngine 的危险模式)
    - 内存映射 (最多20条)
    - 加载模块列表
    """
    lines = []

    lines.append("## Crash Overview\n")
    lines.append(f"Signal: {ctx.signal_analysis}")
    lines.append(f"Architecture: {ctx.metadata.arch}")
    lines.append(f"Kernel: {ctx.metadata.kernel_version}")
    lines.append(f"Distribution: {ctx.metadata.distribution}")

    # --- Crash location summary (explicit for LLM function matching) ---
    top_frame = ctx.resolved_stack[0] if ctx.resolved_stack else None
    if top_frame:
        lines.append("\n## Crash Location\n")
        lines.append(f"Crash Function: {top_frame.function}")
        src_file = getattr(top_frame, 'source_file', '')
        src_line = getattr(top_frame, 'source_line', 0)
        lines.append(f"Source: {src_file}:{src_line}" if src_file and src_line else f"Source: {src_file or 'unknown'}")
        lines.append(f"Instruction Address: {top_frame.address}")
        lines.append(f"Module: {top_frame.module}")

    lines.append("\n## Crash Thread Backtrace\n")
    crash_tid = ctx.crash_thread.tid if ctx.crash_thread else 0
    for frame in ctx.resolved_stack[:50]:
        prefix = "→" if frame.frame_num == crash_tid else " "
        source_info = ""
        src_file = getattr(frame, 'source_file', '')
        src_line = getattr(frame, 'source_line', 0)
        if src_file and src_line:
            source_info = f"({src_file}:{src_line})"
        elif src_file:
            source_info = f"({src_file})"
        lines.append(
            f"{prefix} #{frame.frame_num} {frame.address} in {frame.function}"
            f"{source_info}"
        )

    # --- Correlation hints (danger patterns from CorrelationEngine) ---
    if correlations:
        lines.append("\n## Pre-Analysis Hints (automated correlation)\n")
        for hint in correlations:
            lines.append(f"  ⚡ {hint}")

    lines.append("\n## Registers (crash thread)\n")
    if ctx.crash_thread and ctx.crash_thread.registers_at_crash:
        for reg, val in ctx.crash_thread.registers_at_crash.items():
            lines.append(f"  {reg}: {val}")
    else:
        lines.append("  (no register data)")

    lines.append("\n## Memory Maps (relevant)\n")
    for region in ctx.memory_maps[:20]:
        lines.append(
            f"  {region.start_addr}-{region.end_addr} "
            f"{region.permissions} {region.mapped_file}"
        )

    lines.append("\n## Loaded Modules\n")
    for mod in ctx.loaded_modules:
        lines.append(f"  {mod.name}@{mod.base_addr}  {mod.path}")

    return "\n".join(lines)
