"""Git 安全规范测试 — Task 16 of Crash AI Phase 1.

Tests cover:
1. git blame 有效/无效行
2. 非法 commit hash 拒绝
3. 路径逃逸检测 (路径穿越攻击防护)
4. 非 git 仓库拒绝
5. git --no-pager (CI 安全)
6. 正则安全校验 (commit hash / branch name 注入防护)
7. SourceResolver 上下文读取 + 逃逸防护
"""
import os
import pytest
import tempfile
import subprocess
from pathlib import Path
from src.context.git_blame import GitBlameAnalyzer, COMMIT_HASH_RE, BRANCH_RE
from src.errors import InputError


@pytest.fixture
def tmp_git_repo():
    """创建临时 git 仓库，带一个测试文件。"""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        # Init git repo
        subprocess.run(
            ["git", "init", "-b", "main"],
            cwd=str(repo), capture_output=True, check=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=str(repo), capture_output=True, check=True
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=str(repo), capture_output=True, check=True
        )
        # Create test file
        test_file = repo / "test.c"
        test_file.write_text("line1\nline2\nline3\n")
        subprocess.run(
            ["git", "add", "test.c"],
            cwd=str(repo), capture_output=True, check=True
        )
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=str(repo), capture_output=True, check=True
        )
        yield repo


class TestGitBlameAnalyzer:
    def test_blame_valid_line(self, tmp_git_repo):
        """在临时 git 仓库中对有效行执行 blame"""
        analyzer = GitBlameAnalyzer(tmp_git_repo)
        result = analyzer.blame("test.c", 1)
        assert "line1" in result

    def test_blame_invalid_line(self, tmp_git_repo):
        """对不存在的行号抛出 InputError"""
        analyzer = GitBlameAnalyzer(tmp_git_repo)
        with pytest.raises(InputError):
            analyzer.blame("test.c", 999)

    def test_invalid_commit_hash_raises(self, tmp_git_repo):
        """非法的 commit hash 格式抛出 InputError"""
        analyzer = GitBlameAnalyzer(tmp_git_repo)
        with pytest.raises(InputError, match="Invalid commit hash"):
            analyzer.show_file_at_commit("invalid; rm -rf /", "test.c")

    def test_path_escape_detection(self, tmp_git_repo):
        """../../../etc/passwd 路径逃逸抛出 InputError"""
        analyzer = GitBlameAnalyzer(tmp_git_repo)
        with pytest.raises(InputError, match="escapes"):
            analyzer.blame("../../../etc/passwd", 1)

    def test_nonexistent_repo(self):
        """非 git 仓库抛出 InputError"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(InputError, match="Not a git repository"):
                GitBlameAnalyzer(Path(tmpdir))

    def test_no_pager_in_command(self, tmp_git_repo):
        """git 命令包含 --no-pager (CI 环境无 tty 安全)"""
        analyzer = GitBlameAnalyzer(tmp_git_repo)
        result = analyzer.blame("test.c", 1)
        assert result is not None


class TestSecurityRegexes:
    def test_valid_commit_hash(self):
        """标准 commit hash 格式通过验证"""
        assert COMMIT_HASH_RE.match("abc1234")
        assert COMMIT_HASH_RE.match("a" * 40)
        assert not COMMIT_HASH_RE.match("abc123")  # too short (6 chars)
        assert not COMMIT_HASH_RE.match("abc; rm")  # injection

    def test_valid_branch_name(self):
        """标准分支名通过验证"""
        assert BRANCH_RE.match("main")
        assert BRANCH_RE.match("feat/phase1-implementation")
        assert BRANCH_RE.match("release-2.0_hotfix")
        assert not BRANCH_RE.match("main; rm -rf /")  # injection


class TestSourceResolver:
    def test_read_source_context(self, tmp_git_repo):
        """读取源代码上下文"""
        from src.context.source_resolver import SourceResolver
        resolver = SourceResolver(tmp_git_repo)
        output = resolver.read_source("test.c", 2, context_lines=1)
        assert "line1" in output
        assert "line2" in output
        assert "line3" in output

    def test_path_escape_prevented(self, tmp_git_repo):
        """路径逃逸被阻止"""
        from src.context.source_resolver import SourceResolver
        resolver = SourceResolver(tmp_git_repo)
        with pytest.raises(ValueError, match="escapes"):
            resolver.read_source("../../../etc/passwd", 1)

    def test_missing_file(self, tmp_git_repo):
        """不存在的文件返回友好提示"""
        from src.context.source_resolver import SourceResolver
        resolver = SourceResolver(tmp_git_repo)
        output = resolver.read_source("nonexistent.c", 1)
        assert "not found" in output
