"""GDB Output Parser 单元测试 -- 使用 sample GDB 输出文本。"""
import pytest
from src.symbol.gdb_parser import GDBOutputParser
from src.models.symbol import RawFrame, ResolvedFrame, ThreadState


SAMPLE_THREAD_OUTPUT = """
  Id   Target Id                       Frame
* 1    Thread 0x7ffff7fe1700 (LWP 1234) foo (x=0x0) at src/main.c:42
  2    Thread 0x7ffff7fe2700 (LWP 1235) pthread_cond_wait () at ../sysdeps/unix/sysv/linux/x86_64/pthread_cond_wait.S:185
"""

SAMPLE_THREAD_SINGLE_OUTPUT = """
  Id   Target Id         Frame
* 1    LWP 23            process (buf=0x7fffffffebb0) at main.c:12
"""

SAMPLE_FRAME_OUTPUT = """
#0  0x0000555555555156 in foo (x=0x0) at src/main.c:42
#1  0x0000555555555182 in bar (y=0x7fff) at src/util.c:15
#2  0x00007f1234567890 in ?? ()
"""

SAMPLE_FRAME_INNERMOST_OUTPUT = """
#0  process (buf=0x7fffffffebb0) at main.c:12
#1  0x0000555555555187 in main () at main.c:18
"""

SAMPLE_THREAD_LLDB_OUTPUT = """
* thread #1, name = 'a.out', stop reason = signal SIGSEGV
  thread #2, name = 'a.out'
"""

SAMPLE_THREAD_MACOS_GDB_OUTPUT = """
  Id   Target Id         Frame
* 1    Thread 0x7fff5fbff700  foo (x=0x0) at main.c:12
  2    Thread 0x7fff5fbff800  bar () at util.c:15
"""

SAMPLE_MEMORY_MAP_LINUX = """
    0x555555554000     0x555555555000     r-xp    0x0     08:01   123456   /usr/bin/app
    0x555555555000     0x555555556000     r--p    0x0     08:01   123457   /usr/bin/app
    0x7ffff7a00000     0x7ffff7b00000    r-xp    0x0     254     789012   /lib/x86_64-linux-gnu/libc.so.6
"""

SAMPLE_MEMORY_MAP_MACOS_GDB = """
    0x100000000     0x100001000     rwx     0x0     /Users/user/test/app
    0x100002000     0x100003000     rw-     0x0     /usr/lib/libSystem.B.dylib
    0x7fff5fc00000  0x7fff5fc01000  r-x     0x0     /usr/lib/libc.dylib
"""

SAMPLE_MEMORY_MAP_MACOS_LLDB = """
    [0x0000000100000000-0x0000000100004000) rwx /Users/user/test/app
    [0x0000000100004000-0x0000000100008000) rw- /usr/lib/libSystem.B.dylib
    [0x00007fff5fc00000-0x00007fff5fc01000) r-x /usr/lib/libc.dylib
"""

SAMPLE_MEMORY_MAP_ANONYMOUS = """
    0x7ffff7ff0000     0x7ffff7ff9000     r-xp    0x0     00:00   0
"""

SAMPLE_SHAREDLIBRARY_OUTPUT = """
From                To                  Syms Read   Shared Object Library
0x00007ffff7dd5000  0x00007ffff7df4000  Yes         /lib64/ld-linux-x86-64.so.2
0x00007ffff7a00000  0x00007ffff7bc4000  Yes         /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7bc4000  0x00007ffff7bc5000  Yes (*)     /usr/lib/x86_64-linux-gnu/libSegFault.so
"""

SAMPLE_SHAREDLIBRARY_HEADER_ONLY = """
From                To                  Syms Read   Shared Object Library
"""

SAMPLE_REGISTER_OUTPUT = """
rax             0x0      0
rbx             0x7fff   32767
rcx             0xdead   57005
"""


class TestGDBOutputParser:
    def test_parse_thread_with_crash_marker(self):
        """识别带 * 标记的崩溃线程 (多线程格式)"""
        parser = GDBOutputParser()
        threads = parser.parse_threads(SAMPLE_THREAD_OUTPUT)
        assert len(threads) == 2
        assert threads[0].tid == 1
        assert threads[0].lwpid == 1234
        assert threads[0].is_crashed is True
        assert threads[1].is_crashed is False

    def test_parse_thread_single_lwp(self):
        """识别单线程 LWP 格式的 info threads 输出"""
        parser = GDBOutputParser()
        threads = parser.parse_threads(SAMPLE_THREAD_SINGLE_OUTPUT)
        assert len(threads) == 1
        assert threads[0].tid == 1
        assert threads[0].lwpid == 23
        assert threads[0].is_crashed is True

    def test_parse_thread_lldb_format(self):
        """识别 LLDB thread list 格式 (macOS, 无 LWP 字段)"""
        parser = GDBOutputParser()
        threads = parser.parse_threads(SAMPLE_THREAD_LLDB_OUTPUT)
        assert len(threads) == 2
        assert threads[0].tid == 1
        assert threads[0].lwpid == 1  # macOS 无 LWP, fallback to tid
        assert threads[0].is_crashed is True
        assert threads[1].tid == 2
        assert threads[1].lwpid == 2
        assert threads[1].is_crashed is False

    def test_parse_thread_macos_gdb_format(self):
        """识别 macOS GDB info threads 格式 (无 LWP 字段, 带 Thread 前缀)"""
        parser = GDBOutputParser()
        threads = parser.parse_threads(SAMPLE_THREAD_MACOS_GDB_OUTPUT)
        assert len(threads) == 2
        assert threads[0].tid == 1
        assert threads[0].lwpid == 1  # macOS 无 LWP, fallback to tid
        assert threads[0].is_crashed is True
        assert threads[1].tid == 2
        assert threads[1].lwpid == 2
        assert threads[1].is_crashed is False

    def test_parse_frame_from_bt_full(self):
        """解析含地址的帧 (#0 addr in func at file:line)"""
        parser = GDBOutputParser()
        frames = parser.parse_frames(SAMPLE_FRAME_OUTPUT)
        assert len(frames) == 3
        assert frames[0].frame_num == 0
        assert "foo" in frames[0].function
        assert frames[0].source_file == "src/main.c"
        assert frames[0].source_line == 42
        assert isinstance(frames[0], ResolvedFrame)

    def test_parse_frame_innermost_no_address(self):
        """解析 innermost 帧 (#N func (...) at file:line, 无地址)"""
        parser = GDBOutputParser()
        frames = parser.parse_frames(SAMPLE_FRAME_INNERMOST_OUTPUT)
        assert len(frames) == 2
        assert frames[0].frame_num == 0
        assert frames[0].function == "process"
        assert frames[0].source_file == "main.c"
        assert frames[0].source_line == 12
        assert frames[0].address == ""  # innermost 帧无地址
        assert frames[1].frame_num == 1
        assert frames[1].function == "main"
        assert frames[1].address == "0x0000555555555187"
        assert frames[1].source_line == 18

    def test_parse_frame_unresolved(self):
        """解析未符号化帧 (?? 函数名)"""
        parser = GDBOutputParser()
        frames = parser.parse_frames(
            "#0  0x00007f1234567890 in ?? ()\n"
        )
        assert len(frames) == 1
        assert "??" in frames[0].function

    def test_parse_register_line(self):
        """解析 rax 0x0 格式的寄存器行"""
        parser = GDBOutputParser()
        regs = parser.parse_registers(SAMPLE_REGISTER_OUTPUT)
        assert regs["rax"] == "0x0"
        assert regs["rbx"] == "0x7fff"
        assert regs["rcx"] == "0xdead"

    def test_parse_memory_map_linux(self):
        """解析 Linux info proc mappings 格式 (含 dev/inode 列)"""
        parser = GDBOutputParser()
        maps = parser.parse_memory_maps(SAMPLE_MEMORY_MAP_LINUX)
        assert len(maps) == 3
        assert maps[0].start_addr == "0x555555554000"
        assert maps[0].end_addr == "0x555555555000"
        assert maps[0].permissions == "r-xp"
        assert maps[0].offset == "0x0"
        assert maps[0].mapped_file == "/usr/bin/app"

    def test_parse_memory_map_macos_gdb(self):
        """解析 macOS GDB info proc mappings 格式 (无 dev/inode 列, 3-char perms)"""
        parser = GDBOutputParser()
        maps = parser.parse_memory_maps(SAMPLE_MEMORY_MAP_MACOS_GDB)
        assert len(maps) == 3
        assert maps[0].start_addr == "0x100000000"
        assert maps[0].end_addr == "0x100001000"
        assert maps[0].permissions == "rwx"
        assert maps[0].offset == "0x0"
        assert maps[0].mapped_file == "/Users/user/test/app"

    def test_parse_memory_map_macos_lldb(self):
        """解析 macOS LLDB memory region 格式 ([range) perms path)"""
        parser = GDBOutputParser()
        maps = parser.parse_memory_maps(SAMPLE_MEMORY_MAP_MACOS_LLDB)
        assert len(maps) == 3
        assert maps[0].start_addr == "0x0000000100000000"
        assert maps[0].end_addr == "0x0000000100004000"
        assert maps[0].permissions == "rwx"
        assert maps[0].offset == "0x0"
        assert maps[0].mapped_file == "/Users/user/test/app"

    def test_parse_memory_map_anonymous(self):
        """解析匿名映射 (无 path 列, inode=0)"""
        parser = GDBOutputParser()
        maps = parser.parse_memory_maps(SAMPLE_MEMORY_MAP_ANONYMOUS)
        assert len(maps) == 1
        assert maps[0].start_addr == "0x7ffff7ff0000"
        assert maps[0].end_addr == "0x7ffff7ff9000"
        assert maps[0].permissions == "r-xp"
        assert maps[0].offset == "0x0"
        assert maps[0].mapped_file == ""

    def test_parse_memory_map_empty(self):
        """空输入返回空列表"""
        parser = GDBOutputParser()
        maps = parser.parse_memory_maps("")
        assert maps == []

    def test_parse_modules_standard(self):
        """解析 GDB info sharedlibrary 输出, 提取模块列表"""
        parser = GDBOutputParser()
        modules = parser.parse_modules(SAMPLE_SHAREDLIBRARY_OUTPUT)
        assert len(modules) == 3
        assert modules[0].name == "ld-linux-x86-64.so.2"
        assert modules[0].base_addr == "0x00007ffff7dd5000"
        assert modules[0].path == "/lib64/ld-linux-x86-64.so.2"
        assert modules[1].name == "libc.so.6"
        assert modules[1].base_addr == "0x00007ffff7a00000"
        assert modules[1].path == "/lib/x86_64-linux-gnu/libc.so.6"
        assert modules[2].name == "libSegFault.so"
        assert modules[2].base_addr == "0x00007ffff7bc4000"
        assert modules[2].path == "/usr/lib/x86_64-linux-gnu/libSegFault.so"

    def test_parse_modules_empty(self):
        """空输入返回空列表"""
        parser = GDBOutputParser()
        modules = parser.parse_modules("")
        assert modules == []

    def test_parse_modules_header_only_skipped(self):
        """仅含 header 行的输出, 不产生任何模块"""
        parser = GDBOutputParser()
        modules = parser.parse_modules(SAMPLE_SHAREDLIBRARY_HEADER_ONLY)
        assert modules == []

    def test_gdb_timeout_handling(self):
        """验证 GDB 30s 超时配置存在"""
        from src.symbol.gdb_wrapper import GDBWrapper
        assert GDBWrapper.TIMEOUT == 30
