"""GDB Output Parser 单元测试 -- 使用 sample GDB 输出文本。"""
import pytest
from src.symbol.gdb_parser import GDBOutputParser
from src.models.symbol import RawFrame, ThreadState


SAMPLE_THREAD_OUTPUT = """
  Id   Target Id                       Frame
* 1    Thread 0x7ffff7fe1700 (LWP 1234) foo (x=0x0) at src/main.c:42
  2    Thread 0x7ffff7fe2700 (LWP 1235) pthread_cond_wait () at ../sysdeps/unix/sysv/linux/x86_64/pthread_cond_wait.S:185
"""

SAMPLE_FRAME_OUTPUT = """
#0  0x0000555555555156 in foo (x=0x0) at src/main.c:42
#1  0x0000555555555182 in bar (y=0x7fff) at src/util.c:15
#2  0x00007f1234567890 in ?? ()
"""

SAMPLE_REGISTER_OUTPUT = """
rax             0x0      0
rbx             0x7fff   32767
rcx             0xdead   57005
"""


class TestGDBOutputParser:
    def test_parse_thread_with_crash_marker(self):
        """识别带 * 标记的崩溃线程"""
        parser = GDBOutputParser()
        threads = parser.parse_threads(SAMPLE_THREAD_OUTPUT)
        assert len(threads) == 2
        assert threads[0].tid == 1
        assert threads[0].lwpid == 1234
        assert threads[0].is_crashed is True
        assert threads[1].is_crashed is False

    def test_parse_frame_from_bt_full(self):
        """解析单帧 (#0 addr in func at file:line)"""
        parser = GDBOutputParser()
        frames = parser.parse_frames(SAMPLE_FRAME_OUTPUT)
        assert len(frames) == 3
        assert frames[0].frame_num == 0
        assert "foo" in frames[0].function

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

    def test_gdb_timeout_handling(self):
        """验证 GDB 30s 超时配置存在"""
        from src.symbol.gdb_wrapper import GDBWrapper
        assert GDBWrapper.TIMEOUT == 30
