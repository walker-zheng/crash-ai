"""Symbol resolution models."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    from src.models.crash import CrashContext, CrashMetadata, MemRegion, Module


@dataclass
class RawFrame:
    """原始堆栈帧 (GDB bt 输出)"""

    frame_num: int
    address: str  # 0x00007f1234567890
    function: str  # 函数名 (?? 表示未解析)
    offset: str  # +0x123
    module: str  # libfoo.so


@dataclass
class ResolvedFrame(RawFrame):
    """符号化后的堆栈帧"""

    source_file: str = ""
    source_line: int = 0
    inlined_by: List[str] = field(default_factory=list)
    local_vars: Dict[str, str] = field(default_factory=dict)


@dataclass
class ThreadState:
    """单个线程状态"""

    tid: int  # GDB thread number
    lwpid: int  # LWP ID
    is_crashed: bool  # 是否为崩溃线程
    registers_at_crash: Dict[str, str] = field(default_factory=dict)


@dataclass
class ResolvedCrashContext:
    """符号解析后的增强崩溃上下文"""

    original: CrashContext  # noqa: F821
    resolved_stack: List[ResolvedFrame]
    crash_thread: ThreadState
    signal_analysis: str
    memory_maps: List[MemRegion]  # noqa: F821
    loaded_modules: List[Module]  # noqa: F821
    metadata: CrashMetadata  # noqa: F821
