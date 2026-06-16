"""符号解析编排器 — 协调 GDB + extractors → ResolvedCrashContext。"""
from pathlib import Path
from typing import Optional
from src.symbol.protocol import DebuggerProtocol, ResolvedResult
from src.symbol.gdb_wrapper import GDBWrapper
from src.symbol.gdb_parser import GDBOutputParser
from src.models.crash import CrashContext
from src.models.symbol import ResolvedCrashContext, ThreadState


class SymbolResolver:
    """符号解析编排器。

    流程:
    1. 调用 GDBWrapper.resolve_stack() → ResolvedResult
    2. 解析原始输出 → 帧/线程/寄存器
    3. 组装 ResolvedCrashContext
    4. 降级: 无符号时仍生成 ResolvedCrashContext (function 字段为 "??")
    """

    def __init__(self, debugger: Optional[DebuggerProtocol] = None):
        self.debugger = debugger or GDBWrapper()
        self.parser = GDBOutputParser()

    def resolve(
        self,
        core_path: Path,
        crash_ctx: CrashContext,
        symbol_dir: Optional[Path] = None,
    ) -> ResolvedCrashContext:
        """执行完整符号解析流程。

        Args:
            core_path: core dump 文件路径
            crash_ctx: 原始崩溃上下文
            symbol_dir: 用户提供的符号目录 (可选)

        Returns:
            ResolvedCrashContext, 包含符号化后的堆栈和寄存器
        """
        symbol_paths = [str(symbol_dir)] if symbol_dir else []

        # 1. Get raw GDB output
        try:
            result = self.debugger.resolve_stack(
                core_path=str(core_path),
                symbol_paths=symbol_paths,
            )
        except Exception:
            # GDB unavailable — return minimal context
            return ResolvedCrashContext(
                original=crash_ctx,
                resolved_stack=[],
                crash_thread=ThreadState(tid=0, lwpid=0, is_crashed=True),
                signal_analysis=self._analyze_signal(crash_ctx.signal),
                memory_maps=crash_ctx.memory_maps,
                loaded_modules=crash_ctx.loaded_modules,
                metadata=crash_ctx.metadata,
            )

        # 2. Parse resolved frames from raw output
        resolved_stack = self.parser.parse_frames(result.raw_output)
        if not resolved_stack:
            # Fallback: use empty resolved stack
            resolved_stack = []

        # 3. Get registers from GDB
        try:
            registers = self.debugger.get_registers(str(core_path))
        except Exception:
            registers = crash_ctx.registers

        # 4. Identify crash thread
        crash_thread = self._find_crash_thread(result)
        if crash_thread and registers:
            crash_thread.registers_at_crash = registers

        # 5. Signal analysis text
        signal_analysis = self._analyze_signal(crash_ctx.signal)

        return ResolvedCrashContext(
            original=crash_ctx,
            resolved_stack=resolved_stack,
            crash_thread=crash_thread or ThreadState(tid=0, lwpid=0, is_crashed=True),
            signal_analysis=signal_analysis,
            memory_maps=crash_ctx.memory_maps,
            loaded_modules=crash_ctx.loaded_modules,
            metadata=crash_ctx.metadata,
        )

    def _find_crash_thread(self, result: ResolvedResult) -> Optional[ThreadState]:
        """从 GDB 解析结果中找到崩溃线程 (is_crashed=True)。"""
        for t in result.threads:
            if t.is_crashed:
                return t
        # Fallback: first thread or synthesized
        if result.threads:
            return result.threads[0]
        return None

    @staticmethod
    def _analyze_signal(signal: str) -> str:
        """生成信号含义解释文本。"""
        signal_map = {
            "SIGSEGV": "SIGSEGV: Invalid memory access — likely NULL pointer dereference, buffer overflow, or use-after-free",
            "SIGABRT": "SIGABRT: Process aborted — likely assertion failure or double-free detected by glibc",
            "SIGBUS": "SIGBUS: Bus error — likely unaligned memory access or mmap failure",
            "SIGFPE": "SIGFPE: Floating-point exception — division by zero or integer overflow",
            "SIGILL": "SIGILL: Illegal instruction — corrupted code or incompatible binary",
        }
        return signal_map.get(signal, f"{signal}: Unknown signal")
