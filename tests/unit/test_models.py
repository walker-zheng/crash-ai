"""Tests for shared models layer — Task 2 of Crash AI Phase 1."""
import pytest
from datetime import datetime
from src.models.crash import CrashContext, CrashMetadata, MemRegion, Module
from src.models.symbol import RawFrame, ResolvedFrame, ThreadState, ResolvedCrashContext
from src.models.analysis import AnalysisReport, RootCause, Evidence, CrossValidation, CorrelatedContext
from src.models.version import VersionDiff, BranchScanResult
from src.models.build import BuildProfile, BuildDiff, RustBuildProfile


# =============================================================================
# CrashContext & friends
# =============================================================================

class TestCrashMetadata:
    def test_all_fields(self):
        """CrashMetadata 包含所有系统/环境元信息字段"""
        ts = datetime(2025, 1, 15, 10, 30, 0)
        meta = CrashMetadata(
            timestamp=ts, hostname="server-01", kernel_version="5.15.0",
            distribution="ubuntu-22.04", arch="x86_64", coredump_size_bytes=1048576
        )
        assert meta.timestamp == ts
        assert meta.hostname == "server-01"
        assert meta.kernel_version == "5.15.0"
        assert meta.distribution == "ubuntu-22.04"
        assert meta.arch == "x86_64"
        assert meta.coredump_size_bytes == 1048576


class TestMemRegion:
    def test_all_fields(self):
        """MemRegion 包含内存映射区域各字段"""
        r = MemRegion(
            start_addr="0x7f0000000000", end_addr="0x7f0000100000",
            permissions="r-xp", offset="0x0000", mapped_file="/usr/lib/libc.so.6"
        )
        assert r.start_addr == "0x7f0000000000"
        assert r.end_addr == "0x7f0000100000"
        assert r.permissions == "r-xp"
        assert r.offset == "0x0000"
        assert r.mapped_file == "/usr/lib/libc.so.6"


class TestModule:
    def test_all_fields(self):
        """Module 包含加载模块信息"""
        m = Module(name="libc.so.6", base_addr="0x7f0000000000", path="/usr/lib/libc.so.6", version="2.35")
        assert m.name == "libc.so.6"
        assert m.base_addr == "0x7f0000000000"
        assert m.path == "/usr/lib/libc.so.6"
        assert m.version == "2.35"

    def test_version_default_none(self):
        """version 字段默认 None"""
        m = Module(name="libc.so.6", base_addr="0x7f0000000000", path="/usr/lib/libc.so.6")
        assert m.version is None


class TestCrashContext:
    def test_arch_property_from_metadata(self):
        """arch 属性从 CrashMetadata.arch 透传"""
        meta = CrashMetadata(
            timestamp=datetime.now(), hostname="test", kernel_version="5.15",
            distribution="ubuntu", arch="x86_64", coredump_size_bytes=1024
        )
        ctx = CrashContext(
            signal="SIGSEGV", fault_addr="0x0",
            thread_states=[], registers={}, raw_stack=[],
            memory_maps=[], loaded_modules=[], metadata=meta
        )
        assert ctx.arch == "x86_64"

    def test_minimal_construction(self):
        """最小字段集可构造 CrashContext"""
        meta = CrashMetadata(
            timestamp=datetime.now(), hostname="", kernel_version="",
            distribution="", arch="x86_64", coredump_size_bytes=0
        )
        ctx = CrashContext(
            signal="SIGSEGV", fault_addr="0x0",
            thread_states=[], registers={}, raw_stack=[],
            memory_maps=[], loaded_modules=[], metadata=meta
        )
        assert ctx.signal == "SIGSEGV"
        assert ctx.fault_addr == "0x0"
        assert ctx.registers == {}
        assert ctx.raw_stack == []

    def test_signal_types(self):
        """不同信号类型可正常设置"""
        meta = CrashMetadata(timestamp=datetime.now(), hostname="", kernel_version="", distribution="", arch="x86_64", coredump_size_bytes=0)
        for sig in ["SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE"]:
            ctx = CrashContext(signal=sig, fault_addr="0x0", thread_states=[], registers={},
                               raw_stack=[], memory_maps=[], loaded_modules=[], metadata=meta)
            assert ctx.signal == sig

    def test_arch_aarch64(self):
        """aarch64 架构也支持"""
        meta = CrashMetadata(timestamp=datetime.now(), hostname="", kernel_version="", distribution="", arch="aarch64", coredump_size_bytes=0)
        ctx = CrashContext(signal="SIGSEGV", fault_addr="0x0", thread_states=[], registers={},
                           raw_stack=[], memory_maps=[], loaded_modules=[], metadata=meta)
        assert ctx.arch == "aarch64"


class TestResolvedCrashContext:
    def test_holds_original_reference(self):
        """ResolvedCrashContext.original 持有原始 CrashContext 引用"""
        meta = CrashMetadata(timestamp=datetime.now(), hostname="t", kernel_version="", distribution="", arch="x86_64", coredump_size_bytes=0)
        original = CrashContext(signal="SIGSEGV", fault_addr="0x0", thread_states=[], registers={},
                                raw_stack=[], memory_maps=[], loaded_modules=[], metadata=meta)
        resolved_stack = []
        crash_thread = ThreadState(tid=1, lwpid=1234, is_crashed=True)
        resolved = ResolvedCrashContext(
            original=original,
            resolved_stack=resolved_stack,
            crash_thread=crash_thread,
            signal_analysis="Null pointer dereference at address 0x0",
            memory_maps=[],
            loaded_modules=[],
            metadata=meta
        )
        assert resolved.original is original
        assert resolved.signal_analysis == "Null pointer dereference at address 0x0"

    def test_crash_thread_field(self):
        """ResolvedCrashContext.crash_thread 标记崩溃线程"""
        meta = CrashMetadata(timestamp=datetime.now(), hostname="t", kernel_version="", distribution="", arch="x86_64", coredump_size_bytes=0)
        original = CrashContext(signal="SIGSEGV", fault_addr="0x0", thread_states=[], registers={},
                                raw_stack=[], memory_maps=[], loaded_modules=[], metadata=meta)
        crash_thread = ThreadState(tid=1, lwpid=5678, is_crashed=True, registers_at_crash={"rip": "0x401234"})
        resolved = ResolvedCrashContext(
            original=original, resolved_stack=[], crash_thread=crash_thread,
            signal_analysis="", memory_maps=[], loaded_modules=[], metadata=meta
        )
        assert resolved.crash_thread.lwpid == 5678
        assert resolved.crash_thread.registers_at_crash["rip"] == "0x401234"


# =============================================================================
# Symbol models
# =============================================================================

class TestRawFrame:
    def test_unresolved_frame_fields(self):
        """RawFrame 包含 frame_num/address/function/offset/module"""
        f = RawFrame(frame_num=0, address="0x1234", function="foo", offset="+0x42", module="libfoo.so")
        assert f.frame_num == 0
        assert f.address == "0x1234"
        assert f.function == "foo"
        assert f.offset == "+0x42"
        assert f.module == "libfoo.so"


class TestResolvedFrame:
    def test_inherits_raw_frame(self):
        """ResolvedFrame 继承 RawFrame 所有字段"""
        f = ResolvedFrame(
            frame_num=0, address="0x1234", function="foo", offset="+0x42",
            module="libfoo.so", source_file="src/main.c", source_line=42
        )
        assert f.source_file == "src/main.c"
        assert f.source_line == 42
        assert f.function == "foo"  # inherited
        assert f.address == "0x1234"  # inherited
        assert f.offset == "+0x42"  # inherited
        assert f.module == "libfoo.so"  # inherited

    def test_inlined_by_default_empty(self):
        """inlined_by 默认空列表"""
        f = ResolvedFrame(
            frame_num=0, address="0x1234", function="foo", offset="+0x42",
            module="libfoo.so", source_file="src/main.c", source_line=42
        )
        assert f.inlined_by == []

    def test_local_vars_default_empty(self):
        """local_vars 默认空字典"""
        f = ResolvedFrame(
            frame_num=0, address="0x1234", function="foo", offset="+0x42",
            module="libfoo.so", source_file="src/main.c", source_line=42
        )
        assert f.local_vars == {}

    def test_inlined_by_with_values(self):
        """inlined_by 可包含内联函数名"""
        f = ResolvedFrame(
            frame_num=0, address="0x1234", function="bar", offset="+0x42",
            module="libfoo.so", source_file="src/util.c", source_line=10,
            inlined_by=["foo", "baz"]
        )
        assert len(f.inlined_by) == 2
        assert "foo" in f.inlined_by

    def test_local_vars_with_values(self):
        """local_vars 可包含变量值"""
        f = ResolvedFrame(
            frame_num=0, address="0x1234", function="foo", offset="+0x42",
            module="libfoo.so", source_file="src/main.c", source_line=42,
            local_vars={"ptr": "0x0", "len": "100"}
        )
        assert f.local_vars["ptr"] == "0x0"


class TestThreadState:
    def test_crash_thread_fields(self):
        """ThreadState 包含 tid/lwpid/is_crashed/registers_at_crash"""
        ts = ThreadState(tid=1, lwpid=1234, is_crashed=True, registers_at_crash={"rax": "0x0"})
        assert ts.tid == 1
        assert ts.lwpid == 1234
        assert ts.is_crashed
        assert ts.registers_at_crash["rax"] == "0x0"

    def test_non_crash_thread(self):
        """非崩溃线程 is_crashed=False"""
        ts = ThreadState(tid=2, lwpid=5678, is_crashed=False)
        assert not ts.is_crashed
        assert ts.registers_at_crash == {}

    def test_registers_default_empty(self):
        """registers_at_crash 默认为空字典"""
        ts = ThreadState(tid=1, lwpid=1234, is_crashed=True)
        assert ts.registers_at_crash == {}


# =============================================================================
# Analysis models
# =============================================================================

class TestRootCause:
    def test_all_fields(self):
        """RootCause 包含 category/description/crash_location/trigger_condition"""
        rc = RootCause(
            category="null-pointer",
            description="NULL pointer dereference in config_load()",
            crash_location="src/config.c:120",
            trigger_condition="Null config pointer passed to config_load()"
        )
        assert rc.category == "null-pointer"
        assert rc.description == "NULL pointer dereference in config_load()"
        assert rc.crash_location == "src/config.c:120"
        assert rc.trigger_condition == "Null config pointer passed to config_load()"


class TestEvidence:
    def test_all_fields(self):
        """Evidence 包含 type/description/relevance"""
        ev = Evidence(type="register", description="RAX = 0x0 indicates null pointer", relevance="HIGH")
        assert ev.type == "register"
        assert ev.description == "RAX = 0x0 indicates null pointer"
        assert ev.relevance == "HIGH"

    def test_relevance_values(self):
        """relevance 支持 HIGH/MEDIUM/LOW"""
        for rel in ["HIGH", "MEDIUM", "LOW"]:
            ev = Evidence(type="stack", description="test", relevance=rel)
            assert ev.relevance == rel


class TestAnalysisReport:
    def test_confidence_range(self):
        """confidence 在 0.0~1.0 范围内"""
        rc = RootCause(category="null-pointer", description="NULL deref", crash_location="main.c:42", trigger_condition="NULL config")
        report = AnalysisReport(
            crash_id="test-1", timestamp=datetime.now(),
            root_cause=rc, evidence=[], fix_suggestion="Add NULL check",
            confidence=0.85, raw_llm_response="{}"
        )
        assert 0.0 <= report.confidence <= 1.0
        assert report.confidence == 0.85
        assert report.analysis_notes is None  # default

    def test_multiple_evidence(self):
        """支持多条证据"""
        rc = RootCause(category="oob", description="buffer overflow", crash_location="buf.c:20", trigger_condition="oversized input")
        evidence = [
            Evidence(type="register", description="RBX = 0x41414141", relevance="HIGH"),
            Evidence(type="stack", description="Return address overwritten", relevance="HIGH"),
            Evidence(type="source", description="No bounds check on line 19", relevance="MEDIUM"),
        ]
        report = AnalysisReport(
            crash_id="test-2", timestamp=datetime.now(),
            root_cause=rc, evidence=evidence, fix_suggestion="Add bounds check",
            confidence=0.95, raw_llm_response="{}"
        )
        assert len(report.evidence) == 3

    def test_crash_id_string(self):
        """crash_id 字符串标识"""
        rc = RootCause(category="uaf", description="use after free", crash_location="heap.c:50", trigger_condition="concurrent free")
        report = AnalysisReport(
            crash_id="crash-2025-001", timestamp=datetime.now(),
            root_cause=rc, evidence=[], fix_suggestion="Fix",
            confidence=0.9, raw_llm_response="{}"
        )
        assert report.crash_id == "crash-2025-001"

    def test_fix_suggestion_field(self):
        """fix_suggestion 包含修复建议"""
        rc = RootCause(category="null-pointer", description="NULL deref", crash_location="main.c:42", trigger_condition="NULL config")
        report = AnalysisReport(
            crash_id="test", timestamp=datetime.now(),
            root_cause=rc, evidence=[], fix_suggestion="Add NULL check before config_load()",
            confidence=0.8, raw_llm_response="{}"
        )
        assert "NULL check" in report.fix_suggestion

    def test_analysis_notes_default_none(self):
        """analysis_notes 默认 None"""
        rc = RootCause(category="null-pointer", description="NULL deref", crash_location="main.c:42", trigger_condition="NULL config")
        report = AnalysisReport(
            crash_id="test", timestamp=datetime.now(),
            root_cause=rc, evidence=[], fix_suggestion="Fix",
            confidence=0.8, raw_llm_response="{}"
        )
        assert report.analysis_notes is None

    def test_analysis_notes_custom(self):
        """analysis_notes 可自定义"""
        rc = RootCause(category="null-pointer", description="NULL deref", crash_location="main.c:42", trigger_condition="NULL config")
        report = AnalysisReport(
            crash_id="test", timestamp=datetime.now(),
            root_cause=rc, evidence=[], fix_suggestion="Fix",
            confidence=0.8, raw_llm_response="{}",
            analysis_notes="Internal error, retry suggested"
        )
        assert report.analysis_notes == "Internal error, retry suggested"

    def test_raw_llm_response(self):
        """raw_llm_response 保留 LLM 原始输出"""
        rc = RootCause(category="null-pointer", description="NULL deref", crash_location="main.c:42", trigger_condition="NULL config")
        raw = '{"root_cause": {"category": "null-pointer"}}'
        report = AnalysisReport(
            crash_id="test", timestamp=datetime.now(),
            root_cause=rc, evidence=[], fix_suggestion="Fix",
            confidence=0.8, raw_llm_response=raw
        )
        assert report.raw_llm_response == raw


class TestCrossValidation:
    def test_consensus_and_contradiction(self):
        """CrossValidation 包含共识和矛盾信息"""
        cv = CrossValidation(
            source_a="register_analysis",
            source_b="stack_analysis",
            consensus="Null pointer dereference confirmed",
            contradiction="Register suggests address 0x0, stack shows offset from 0x7f"
        )
        assert cv.source_a == "register_analysis"
        assert cv.source_b == "stack_analysis"
        assert cv.consensus == "Null pointer dereference confirmed"
        assert cv.contradiction == "Register suggests address 0x0, stack shows offset from 0x7f"

    def test_contradiction_default_none(self):
        """contradiction 默认 None"""
        cv = CrossValidation(
            source_a="a", source_b="b",
            consensus="Both agree"
        )
        assert cv.contradiction is None


class TestCorrelatedContext:
    def test_default_lists(self):
        """CorrelatedContext 列表字段默认空列表"""
        cc = CorrelatedContext()
        assert cc.timeline_alignment == []
        assert cc.register_var_map == {}
        assert cc.danger_patterns == []
        assert cc.lock_analysis is None
        assert cc.memory_analysis is None

    def test_custom_values(self):
        """CorrelatedContext 可填充字段"""
        cc = CorrelatedContext(
            timeline_alignment=["t1: alloc", "t2: free", "t3: use"],
            register_var_map={"rdi": "ptr"},
            lock_analysis="No locks held at crash time",
            memory_analysis="Heap chunk at 0x5555 already freed",
            danger_patterns=["use-after-free", "dangling-pointer"]
        )
        assert len(cc.timeline_alignment) == 3
        assert cc.register_var_map["rdi"] == "ptr"
        assert cc.lock_analysis == "No locks held at crash time"
        assert cc.memory_analysis == "Heap chunk at 0x5555 already freed"
        assert len(cc.danger_patterns) == 2


# =============================================================================
# Version models (Phase 2 placeholder)
# =============================================================================

class TestVersionDiff:
    def test_default_placeholder(self):
        """VersionDiff 占位字段均有默认值"""
        vd = VersionDiff()
        assert vd.commit_a == ""
        assert vd.commit_b == ""
        assert vd.changed_files == []
        assert vd.diff_summary == ""

    def test_custom_values(self):
        """VersionDiff 可填充值"""
        vd = VersionDiff(
            commit_a="abc123", commit_b="def456",
            changed_files=["src/main.c", "src/util.c"],
            diff_summary="Fixed buffer overflow in main.c"
        )
        assert vd.commit_a == "abc123"
        assert vd.commit_b == "def456"
        assert len(vd.changed_files) == 2
        assert vd.diff_summary == "Fixed buffer overflow in main.c"


class TestBranchScanResult:
    def test_default_placeholder(self):
        """BranchScanResult 占位字段均有默认值"""
        bsr = BranchScanResult()
        assert bsr.branch == ""
        assert bsr.affected_commits == []
        assert bsr.common_root_cause is None

    def test_custom_values(self):
        """BranchScanResult 可填充值"""
        bsr = BranchScanResult(
            branch="release/2.0",
            affected_commits=["abc123", "def456"],
            common_root_cause="Null pointer deref in config parser"
        )
        assert bsr.branch == "release/2.0"
        assert len(bsr.affected_commits) == 2
        assert bsr.common_root_cause == "Null pointer deref in config parser"


# =============================================================================
# Build models (Phase 3 placeholder)
# =============================================================================

class TestBuildProfile:
    def test_default_placeholder(self):
        """BuildProfile 占位字段均有默认值"""
        bp = BuildProfile()
        assert bp.compiler == ""
        assert bp.flags == []
        assert bp.optimization_level == ""

    def test_custom_values(self):
        """BuildProfile 可填充值"""
        bp = BuildProfile(
            compiler="gcc-12", flags=["-O2", "-Wall", "-DNDEBUG"],
            optimization_level="-O2"
        )
        assert bp.compiler == "gcc-12"
        assert len(bp.flags) == 3
        assert bp.optimization_level == "-O2"


class TestBuildDiff:
    def test_default_none(self):
        """BuildDiff profile 默认 None"""
        bd = BuildDiff()
        assert bd.profile_a is None
        assert bd.profile_b is None
        assert bd.flag_diff == []

    def test_custom_values(self):
        """BuildDiff 可填充值"""
        pa = BuildProfile(compiler="gcc-11", flags=["-O0"])
        pb = BuildProfile(compiler="gcc-12", flags=["-O2"])
        bd = BuildDiff(profile_a=pa, profile_b=pb, flag_diff=["-O0 -> -O2"])
        assert bd.profile_a.compiler == "gcc-11"
        assert bd.profile_b.compiler == "gcc-12"
        assert bd.flag_diff == ["-O0 -> -O2"]


class TestRustBuildProfile:
    def test_default_placeholder(self):
        """RustBuildProfile 占位字段默认值"""
        rbp = RustBuildProfile()
        assert rbp.compile_commands_path == ""

    def test_custom_path(self):
        """RustBuildProfile 可指定 compile_commands.json 路径"""
        rbp = RustBuildProfile(compile_commands_path="build/compile_commands.json")
        assert rbp.compile_commands_path == "build/compile_commands.json"
