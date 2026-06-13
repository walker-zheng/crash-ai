"""调试器抽象接口 — DebuggerProtocol ABC。"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List

from src.models.symbol import ResolvedFrame, ThreadState


@dataclass
class ResolvedResult:
    """符号解析结果容器"""

    stack: List[ResolvedFrame] = field(default_factory=list)
    registers: Dict[str, str] = field(default_factory=dict)
    threads: List[ThreadState] = field(default_factory=list)
    raw_output: str = ""  # 保留原始 GDB 输出用于审计


class DebuggerProtocol(ABC):
    """调试器抽象接口 — 支持 GDB/LLDB 互换。"""

    @abstractmethod
    def resolve_stack(
        self, core_path: str, symbol_paths: list[str]
    ) -> ResolvedResult:
        """解析崩溃堆栈, 返回符号化结果。"""
        ...

    @abstractmethod
    def get_registers(self, core_path: str) -> Dict[str, str]:
        """获取崩溃时刻寄存器快照。"""
        ...

    @abstractmethod
    def get_threads(self, core_path: str) -> list[ThreadState]:
        """获取所有线程状态。"""
        ...
