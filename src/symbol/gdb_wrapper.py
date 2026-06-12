"""GDB 非交互模式包装器 — DebuggerProtocol 实现。"""
import subprocess
from typing import Dict, List

from src.symbol.protocol import DebuggerProtocol, ResolvedResult
from src.symbol.gdb_parser import GDBOutputParser


class GDBWrapper(DebuggerProtocol):
    """GDB 非交互模式包装器。

    gdb -batch -nx -nh -q (禁止用户/system .gdbinit)
    timeout=30s, shell=False
    """

    TIMEOUT = 30

    def __init__(self, gdb_path: str = "gdb"):
        self.gdb_path = gdb_path
        self.parser = GDBOutputParser()

    def resolve_stack(
        self, core_path: str, symbol_paths: list[str]
    ) -> ResolvedResult:
        """执行 GDB 批处理栈解析。"""
        symbol_args = []
        for sp in symbol_paths:
            symbol_args.extend(["-ex", f"set debug-file-directory {sp}"])

        cmd = [
            self.gdb_path,
            "-batch", "-nx", "-nh", "-q",
            "-ex", "info threads",
            "-ex", "thread apply all bt full",
            *symbol_args,
            "-c", core_path,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.TIMEOUT,
            shell=False,
        )

        raw = result.stdout if result.returncode == 0 else result.stderr

        return ResolvedResult(
            stack=[],  # parsed later by resolver
            registers={},
            threads=self.parser.parse_threads(raw),
            raw_output=raw,
        )

    def get_registers(self, core_path: str) -> Dict[str, str]:
        """通过 GDB info all-registers 获取寄存器快照。"""
        cmd = [
            self.gdb_path,
            "-batch", "-nx", "-nh", "-q",
            "-ex", "info all-registers",
            "-c", core_path,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.TIMEOUT,
            shell=False,
        )
        return self.parser.parse_registers(result.stdout)

    def get_threads(self, core_path: str) -> list:
        """通过 GDB info threads 获取线程列表。"""
        cmd = [
            self.gdb_path,
            "-batch", "-nx", "-nh", "-q",
            "-ex", "info threads",
            "-c", core_path,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.TIMEOUT,
            shell=False,
        )
        return self.parser.parse_threads(result.stdout)
