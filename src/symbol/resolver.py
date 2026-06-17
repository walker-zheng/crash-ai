"""符号解析编排器 — 协调 GDB + extractors → ResolvedCrashContext。"""
import struct
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
    1. 从 core dump 提取可执行文件路径 (exe_path)
    2. 调用 GDBWrapper.resolve_stack() → ResolvedResult (传入 exe_path)
    3. 解析原始输出 → 帧/线程/寄存器
    4. 组装 ResolvedCrashContext
    5. 降级: 无符号时仍生成 ResolvedCrashContext (function 字段为 "??")
    """

    def __init__(self, debugger: Optional[DebuggerProtocol] = None):
        self.debugger = debugger or GDBWrapper()
        self.parser = GDBOutputParser()

    @staticmethod
    def _extract_exe_path(core_path: Path) -> str | None:
        """从 core dump 的 NT_PRPSINFO note 中提取可执行文件路径。

        NT_PRPSINFO 结构 (x86_64 Linux):
          offset  size  field
          0       4     pr_state+pr_sname+pr_zomb+pr_nice
          4       4     padding (for unsigned long alignment)
          8       8     pr_flag (unsigned long)
          16      4     pr_uid
          20      4     pr_gid
          24      4     pr_pid
          28      4     pr_ppid
          32      4     pr_pgrp
          36      4     pr_sid
          40      16    pr_fname[16]
          56      80    pr_psargs[80]  ← 可执行文件命令行
          总计 136 bytes

        Elf64_Nhdr:
          offset  size  field
          0       4     n_namesz
          4       4     n_descsz
          8       4     n_type
          12      n_namesz (padded to 4)  name
          12+pad  n_descsz (padded to 4)  desc (PRPSINFO data)
        """
        try:
            with open(core_path, "rb") as f:
                data = f.read()
            # ELF header: e_phoff at offset 0x20 (64-bit)
            if len(data) < 0x40:
                return None
            e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
            e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
            e_phnum = struct.unpack_from("<H", data, 0x38)[0]

            for i in range(e_phnum):
                base = e_phoff + i * e_phentsize
                if base + 0x38 > len(data):
                    break
                p_type = struct.unpack_from("<I", data, base)[0]
                # PT_NOTE = 4
                if p_type != 4:
                    continue
                # Elf64_Phdr: p_offset at +8, p_filesz at +32
                p_offset = struct.unpack_from("<Q", data, base + 8)[0]
                p_filesz = struct.unpack_from("<Q", data, base + 32)[0]
                if p_offset + p_filesz > len(data):
                    continue
                # Scan notes in PT_NOTE segment
                note_end = p_offset + p_filesz
                pos = p_offset
                while pos + 12 <= note_end:
                    n_namesz = struct.unpack_from("<I", data, pos)[0]
                    n_descsz = struct.unpack_from("<I", data, pos + 4)[0]
                    n_type = struct.unpack_from("<I", data, pos + 8)[0]
                    name_padded = (n_namesz + 3) & ~3
                    desc_start = pos + 12 + name_padded
                    # NT_PRPSINFO = 3
                    if n_type == 3 and n_descsz >= 136:
                        # pr_fname at +40, pr_psargs at +56
                        pr_psargs_offset = desc_start + 56
                        if pr_psargs_offset + 80 <= len(data):
                            raw = data[pr_psargs_offset:pr_psargs_offset + 80]
                            null_idx = raw.find(b"\x00")
                            if null_idx >= 0:
                                raw = raw[:null_idx]
                            cmdline = raw.decode("latin-1", errors="replace").strip()
                            exe_path = cmdline.split()[0] if cmdline else None
                            if exe_path:
                                return exe_path
                    # Advance to next note
                    desc_padded = (n_descsz + 3) & ~3
                    pos = pos + 12 + name_padded + desc_padded
        except (OSError, struct.error, IndexError):
            pass
        return None

    def resolve(
        self,
        core_path: Path,
        crash_ctx: CrashContext,
        symbol_dir: Optional[Path] = None,
        exe_path: Optional[str] = None,
    ) -> ResolvedCrashContext:
        """执行完整符号解析流程。

        Args:
            core_path: core dump 文件路径
            crash_ctx: 原始崩溃上下文
            symbol_dir: 用户提供的符号目录 (可选)
            exe_path: 可执行文件路径 (可选, 不提供则自动从core dump提取)

        Returns:
            ResolvedCrashContext, 包含符号化后的堆栈和寄存器
        """
        symbol_paths = [str(symbol_dir)] if symbol_dir else []
        if not exe_path:
            exe_path = self._extract_exe_path(core_path)

        # 1. Get raw GDB output
        try:
            result = self.debugger.resolve_stack(
                core_path=str(core_path),
                symbol_paths=symbol_paths,
                exe_path=exe_path,
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
            "SIGTRAP": "SIGTRAP: Breakpoint trap — macOS LLDB stack-smash or double-free detection (EXC_BREAKPOINT)",
        }
        return signal_map.get(signal, f"{signal}: Unknown signal")
