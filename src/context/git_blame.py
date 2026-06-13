"""Git blame + show — 单版本源码上下文增强。

安全规范 (所有 git 调用):
1. git --no-pager (CI 环境无 tty)
2. -- 分隔符 (防止选项注入)
3. 分支名验证: ^[a-zA-Z0-9._/\\-]+$
4. commit hash 验证: ^[0-9a-f]{7,40}$
5. 文件路径 os.path.realpath() 前缀检查
6. subprocess.run list 参数 + shell=False
"""
import re
import os
import subprocess
from pathlib import Path
from src.errors import InputError


# 安全校验正则
BRANCH_RE = re.compile(r"^[a-zA-Z0-9._/\-]+$")
COMMIT_HASH_RE = re.compile(r"^[0-9a-f]{7,40}$")


class GitBlameAnalyzer:
    """git blame 分析器 — 定位崩溃代码的最后修改者。

    使用安全模式调用 git 命令，防止命令注入和路径逃逸攻击。

    Args:
        repo_path: git 仓库的根目录
    """

    def __init__(self, repo_path: Path):
        self.repo_path = Path(os.path.realpath(repo_path))
        self._validate_repo()

    def _validate_repo(self):
        """验证 repo_path 是有效的 git 仓库。

        Raises:
            InputError: 不是有效的 git 仓库
        """
        if not (self.repo_path / ".git").exists():
            raise InputError(f"Not a git repository: {self.repo_path}")
        try:
            subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                capture_output=True, text=True,
                cwd=str(self.repo_path), timeout=5,
                shell=False, check=True,
            )
        except subprocess.CalledProcessError:
            raise InputError(f"Not a valid git repository: {self.repo_path}")

    def blame(self, file_path: str, line: int) -> str:
        """对指定文件的指定行执行 git blame。

        Args:
            file_path: 相对 repo 根目录的文件路径
            line: 行号 (1-indexed)

        Returns:
            git blame 输出

        Raises:
            InputError: 文件路径不在 repo 内或 git 命令失败
        """
        full_path = self._resolve_path(file_path)
        cmd = [
            "git", "--no-pager", "blame",
            "-L", f"{line},{line}",
            "--", str(full_path)
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.repo_path),
                timeout=10,
                shell=False,
            )
            result.check_returncode()
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            raise InputError(f"git blame timed out for {file_path}:{line}")
        except subprocess.CalledProcessError as e:
            raise InputError(f"git blame failed: {e.stderr}")

    def show_file_at_commit(self, commit: str, file_path: str) -> str:
        """获取指定 commit 时的文件内容。

        Args:
            commit: commit hash (7-40 hex chars)
            file_path: 相对路径

        Returns:
            文件内容

        Raises:
            InputError: commit hash 格式不合法或 git 命令失败
        """
        if not COMMIT_HASH_RE.match(commit):
            raise InputError(f"Invalid commit hash format: {commit}")

        cmd = [
            "git", "--no-pager", "show",
            "--", f"{commit}:{file_path}"
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.repo_path),
                timeout=10,
                shell=False,
            )
            result.check_returncode()
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise InputError(f"git show failed: {e.stderr}")

    def _resolve_path(self, file_path: str) -> Path:
        """展开路径并做前缀安全检查。

        Raises:
            InputError: 路径逃逸 repo 根目录
        """
        full = Path(os.path.realpath(self.repo_path / file_path))
        repo_str = str(self.repo_path)
        full_str = str(full)
        # 使用 commonpath 防止软链接等技巧绕过 startswith 检查
        if os.path.commonpath([repo_str, full_str]) != repo_str:
            raise InputError(
                f"Path escapes repo root: {file_path} -> {full}"
            )
        return full
