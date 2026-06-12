"""GDB 输出解析器 — 正则提取线程/帧/寄存器/内存映射。"""
import re
from typing import Dict, List

from src.models.crash import MemRegion, Module
from src.models.symbol import RawFrame, ThreadState


# GDB output format examples:
#   Thread 1 (LWP 1234)  (crash thread *)
#   #0  0x00007f1234567890 in foo (arg=0x0) at src/main.c:42

THREAD_RE = re.compile(
    r"^\s*\*?\s*(\d+)\s+\S+.*\(LWP\s+(\d+)\)"
)
FRAME_RE = re.compile(
    r"^#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)\s*\(.*\)"
    r"(?:\s+at\s+(.+):(\d+))?"
)
FRAME_NO_SOURCE_RE = re.compile(
    r"^#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)"
)
REGISTER_RE = re.compile(
    r"^(\w+)\s+(0x[0-9a-fA-F]+)\s+\d+"
)
MEMORY_MAP_RE = re.compile(
    r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+"
    r"([r\-][w\-][x\-][sp\-])\s+(0x[0-9a-fA-F]+)"
    r"\s+\S+\s+\S+\s+(.+)"
)


class GDBOutputParser:
    """解析 GDB 批处理模式的文本输出。"""

    def parse_threads(self, raw: str) -> List[ThreadState]:
        """解析 info threads 输出, 提取线程列表"""
        threads = []
        for line in raw.split("\n"):
            m = THREAD_RE.search(line)
            if m:
                is_crashed = line.strip().startswith("*")
                threads.append(ThreadState(
                    tid=int(m.group(1)),
                    lwpid=int(m.group(2)),
                    is_crashed=is_crashed,
                ))
        return threads

    def parse_frames(self, raw: str) -> List[RawFrame]:
        """解析 thread apply all bt full 输出, 提取所有帧"""
        frames = []
        for line in raw.split("\n"):
            m = FRAME_RE.search(line)
            if m:
                frames.append(RawFrame(
                    frame_num=int(m.group(1)),
                    address=m.group(2),
                    function=m.group(3),
                    offset="",  # GDB doesn't always show offset separately
                    module=self._extract_module(
                        m.group(4) if m.lastindex and m.lastindex >= 4 else ""
                    ),
                ))
                continue
            m = FRAME_NO_SOURCE_RE.search(line)
            if m:
                frames.append(RawFrame(
                    frame_num=int(m.group(1)),
                    address=m.group(2),
                    function=m.group(3),
                    offset="",
                    module="??",
                ))
        return frames

    def parse_registers(self, raw: str) -> Dict[str, str]:
        """解析 info all-registers 输出, 提取寄存器值"""
        regs = {}
        for line in raw.split("\n"):
            m = REGISTER_RE.search(line)
            if m:
                regs[m.group(1)] = m.group(2)
        return regs

    def parse_memory_maps(self, raw: str) -> list[MemRegion]:
        """解析 info proc mappings 输出"""
        maps = []
        for line in raw.split("\n"):
            m = MEMORY_MAP_RE.search(line)
            if m:
                maps.append(MemRegion(
                    start_addr=m.group(1),
                    end_addr=m.group(2),
                    permissions=m.group(3),
                    offset=m.group(4),
                    mapped_file=m.group(5).strip(),
                ))
        return maps

    def parse_modules(self, raw: str) -> list[Module]:
        """解析 info sharedlibrary 输出"""
        modules = []
        for line in raw.split("\n"):
            # Format: 0x7f...  0x7f...  Yes (*)  /lib/x86_64-linux-gnu/libc.so.6
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0].startswith("0x"):
                modules.append(Module(
                    name=parts[-1].split("/")[-1] if "/" in parts[-1] else parts[-1],
                    base_addr=parts[0],
                    path=parts[-1] if "/" in parts[-1] else parts[-1],
                ))
        return modules

    @staticmethod
    def _extract_module(source: str) -> str:
        """从源文件路径推断模块名"""
        if "/" in source:
            return source.split("/")[-1].split(".")[0]
        return "??"
