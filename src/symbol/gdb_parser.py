"""GDB 输出解析器 — 正则提取线程/帧/寄存器/内存映射。"""
import re
from typing import Dict, List

from src.models.crash import MemRegion, Module
from src.models.symbol import RawFrame, ResolvedFrame, ThreadState


# Output format examples:
#
# GDB info threads 输出 (Linux):
#   * 1    LWP 23            process (...) at main.c:12        (单线程)
#   * 1    Thread 0x7fff... (LWP 1234) foo (...) at main.c:42  (多线程)
#
# GDB info threads 输出 (macOS, 无 LWP 字段):
#   * 1    Thread 0x7fff...  foo (...) at main.c:12
#
# LLDB thread list 输出 (macOS, 无 LWP 字段):
#   * thread #1, name = 'a.out'
#     thread #2, name = 'a.out'
#
# thread apply all bt 输出:
#   Thread 1 (LWP 23):
#   #0  process (buf=0x...) at main.c:12       (innermost: 无地址)
#   #1  0x0000555555555187 in main () at main.c:18  (含地址)
#   #2  0x00007f1234567890 in ?? ()             (未符号化)

THREAD_RE = re.compile(
    r"^\s*\*?\s*(?:"
    r"(\d+)\s+.*?LWP\s+(\d+)"      # GDB with LWP: "1    LWP 23" / "1    Thread ... (LWP 1234)"
    r"|"
    r"(\d+)\s+(?:Thread|process)"   # GDB without LWP (macOS): "1    Thread 0x7fff..."
    r"|"
    r"thread\s+#?(\d+)"             # LLDB: "thread #1" / "thread 1"
    r")"
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
# 内存映射正则: 支持 GDB info proc mappings + LLDB memory region 双格式
#
# GDB info proc mappings (Linux/macOS):
#   0xADDR 0xADDR perms offset [dev inode] path
#
# LLDB memory region (macOS):
#   [0xADDR-0xADDR) perms [path]
#
# Group numbering:
#   (1)/(2): GDB start/end addr    | (3)/(4): LLDB start/end addr
#   (5) permissions  (6) offset    | (7) path (optional)
MEMORY_MAP_RE = re.compile(
    r"^\s*"
    r"(?:"
    r"(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)"          # GDB: two 0x-addr
    r"|"
    r"\[(0x[0-9a-fA-F]+)-(0x[0-9a-fA-F]+)\)"          # LLDB: [range)
    r")"
    r"\s+"
    # Permissions: case-insensitive, 3-4 chars (r-xp / rwx / ---p / R-X)
    r"((?:[rR-][wW-][xX-](?:[pPsS-])?))"
    # GDB offset + optional dev:inode columns
    r"(?:\s+(0x[0-9a-fA-F]+)(?:\s+\S+\s+\S+)?)?"
    # Optional path (anonymous mappings have no path)
    r"(?:\s+(.*))?"
)


class GDBOutputParser:
    """解析 GDB 批处理模式的文本输出。"""

    def parse_threads(self, raw: str) -> List[ThreadState]:
        """解析 info threads / thread list 输出, 提取线程列表。

        支持三种格式:
          (1) GDB with LWP:     * 1    LWP 1234
                               * 1    Thread 0x7fff... (LWP 1234)
          (2) GDB no LWP (macOS): * 1    Thread 0x7fff...
          (3) LLDB:              * thread #1, ... /   thread #2, ...
        """
        threads = []
        for line in raw.split("\n"):
            m = THREAD_RE.search(line)
            if m:
                is_crashed = line.strip().startswith("*")
                if m.group(1) is not None:
                    # GDB format — has LWP
                    tid = int(m.group(1))
                    lwpid = int(m.group(2))
                elif m.group(3) is not None:
                    # GDB format — no LWP (macOS GDB omits LWP)
                    tid = int(m.group(3))
                    lwpid = tid
                else:
                    # LLDB format — no LWP, use tid as lwpid
                    tid = int(m.group(4))
                    lwpid = tid  # macOS has no LWP
                threads.append(ThreadState(
                    tid=tid,
                    lwpid=lwpid,
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
        """解析内存映射输出 (GDB info proc mappings / LLDB memory region / image list)。"""
        maps = []
        for line in raw.split("\n"):
            m = MEMORY_MAP_RE.search(line)
            if m:
                start_addr = m.group(1) or m.group(3)   # GDB or LLDB start
                end_addr = m.group(2) or m.group(4)      # GDB or LLDB end
                perms = m.group(5)
                offset = m.group(6) or "0x0"             # LLDB 无 offset 列
                mapped_file = (m.group(7) or "").strip()
                maps.append(MemRegion(
                    start_addr=start_addr,
                    end_addr=end_addr,
                    permissions=perms,
                    offset=offset,
                    mapped_file=mapped_file,
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
