"""LLDB Stub — Phase 2 补全。"""
from typing import Dict, List

from src.symbol.protocol import DebuggerProtocol, ResolvedResult


class LLDBWrapper(DebuggerProtocol):
    """LLDB 调试器包装器 (macOS)。Phase 1: raise NotImplementedError。"""

    def resolve_stack(
        self, core_path: str, symbol_paths: list[str]
    ) -> ResolvedResult:
        raise NotImplementedError("LLDB backend is planned for Phase 2")

    def get_registers(self, core_path: str) -> Dict[str, str]:
        raise NotImplementedError("LLDB backend is planned for Phase 2")

    def get_threads(self, core_path: str) -> list:
        raise NotImplementedError("LLDB backend is planned for Phase 2")
