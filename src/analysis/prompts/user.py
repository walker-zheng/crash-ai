"""User prompt 构建函数 — 将 ResolvedCrashContext 序列化为 LLM 输入。"""
from src.models.symbol import ResolvedCrashContext


def build_user_prompt(ctx: ResolvedCrashContext) -> str:
    """构建发送给 LLM 的 user prompt。

    包含:
    - 崩溃概览 (信号、架构、内核、发行版、core 大小)
    - 崩溃线程堆栈回溯 (最多50帧, 崩溃帧用 → 标记)
    - 寄存器快照
    - 内存映射 (最多20条)
    - 加载模块列表
    """
    lines = []

    lines.append("## Crash Context\n")
    lines.append(f"Signal: {ctx.signal_analysis}")
    lines.append(f"Architecture: {ctx.metadata.arch}")
    lines.append(f"Kernel: {ctx.metadata.kernel_version}")
    lines.append(f"Distribution: {ctx.metadata.distribution}")
    lines.append(f"Core Dump Size: {ctx.metadata.coredump_size_bytes} bytes")

    lines.append("\n## Crash Thread Backtrace\n")
    crash_tid = ctx.crash_thread.tid if ctx.crash_thread else 0
    for frame in ctx.resolved_stack[:50]:
        prefix = "→" if frame.frame_num == crash_tid else " "
        # Handle both RawFrame (no source_file) and ResolvedFrame
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
