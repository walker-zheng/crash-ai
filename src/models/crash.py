"""Core crash data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from src.models.symbol import RawFrame, ThreadState


@dataclass
class CrashMetadata:
    """系统与环境元信息"""

    timestamp: datetime
    hostname: str
    kernel_version: str
    distribution: str
    arch: str  # 'x86_64' / 'aarch64'
    coredump_size_bytes: int


@dataclass
class MemRegion:
    """内存映射区域"""

    start_addr: str
    end_addr: str
    permissions: str  # 'r-xp' / 'rw-p' / ...
    offset: str
    mapped_file: str  # 映射文件路径或 '[anon]'


@dataclass
class Module:
    """加载的模块/共享库"""

    name: str  # libc.so.6
    base_addr: str
    path: str
    version: Optional[str] = None


@dataclass
class CrashContext:
    """从 core dump 提取的原始崩溃上下文"""

    signal: str  # SIGSEGV, SIGABRT, SIGBUS, etc.
    fault_addr: str  # 故障地址
    thread_states: List[ThreadState]  # noqa: F821
    registers: Dict[str, str]  # CPU 寄存器快照
    raw_stack: List[RawFrame]  # noqa: F821
    memory_maps: List[MemRegion]  # 内存映射
    loaded_modules: List[Module]  # 加载模块
    metadata: CrashMetadata  # 系统/环境元信息

    @property
    def arch(self) -> str:
        """从 arch 字段检测架构"""
        return self.metadata.arch
