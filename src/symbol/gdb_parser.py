"""GDB 输出解析器 — 正则提取线程/帧/寄存器/内存映射。"""
import re
from typing import Dict, List

from src.models.crash import MemRegion, Module
from src.models.symbol import RawFrame, ResolvedFrame, ThreadState


# GDB output format examples:
#
# info threads 输出:
#   * 1    LWP 23            process (...) at main.c:12        (单线程)
#   * 1    Thread 0x7fff... (LWP 1234) foo (...) at main.c:42  (多线程)
#
# thread apply all bt 输出:
#   Thread 1 (LWP 23):
#   #0  process (buf=0x...) at main.c:12       (innermost: 无地址)
#   #1  0x0000555555555187 in main () at main.c:18  (含地址)
#   #2  0x00007f1234567890 in ?? ()             (未符号化)

THREAD_RE = re.compile(
    r"^\s*\*?\s*(\d+)\s+.*?LWP\s+(\d+)"  # "  * 1    LWP 23" / "  * 1    Thread ... (LWP 1234)"
)
FRAME_RE = re.compile(
    r"^#(\d+)\s+"
    r"(?:(0x[0-9a-fA-F]+)\s+in\s+)?"
    r"(\S+)\s*\(.*?\)"
    r"(?:\s+at\s+(.+?):(\d+))?"
)
FRAME_NO_SOURCE_RE = re.compile(
    r"^#(\d+)\s+"
    r"(?:(0x[0-9a-fA-F]+)\s+in\s+)?"
    r"(\S+)"
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

    def parse_frames(self, raw: str) -> List[ResolvedFrame]:
        """解析 thread apply all bt full 输出, 提取所有帧 (含源文件信息)。

        支持两种格式:
          (1) #N  0xADDR in FUNC (...) [at FILE:LINE]
          (2) #N  FUNC (...) at FILE:LINE            (innermost, GDB 省略地址)

        注意: GDB 在 info threads 和 backtrace 中可能重复输出相同帧,
        去重逻辑按 (frame_num, function, source_file, source_line) 去重。
        """
        frames: list[ResolvedFrame] = []
        seen: set[tuple[int, str, str, int]] = set()
        for line in raw.split("\n"):
            m = FRAME_RE.search(line)
            if m:
                addr = m.group(2) or ""
                file_path = m.group(4) or ""
                line_num = int(m.group(5)) if m.group(5) else 0
                frame_num = int(m.group(1))
                func = m.group(3)
                key = (frame_num, func, file_path, line_num)
                if key not in seen:
                    seen.add(key)
                    frames.append(ResolvedFrame(
                        frame_num=frame_num,
                        address=addr,
                        function=func,
                        offset="",
                        module=self._extract_module(file_path),
                        source_file=file_path,
                        source_line=line_num,
                    ))
                continue
            m = FRAME_NO_SOURCE_RE.search(line)
            if m:
                addr = m.group(2) or ""
                frame_num = int(m.group(1))
                func = m.group(3)
                key = (frame_num, func, "", 0)
                if key not in seen:
                    seen.add(key)
                    frames.append(ResolvedFrame(
                        frame_num=frame_num,
                        address=addr,
                        function=func,
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
