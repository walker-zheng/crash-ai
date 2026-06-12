"""源文件定位与读取。

根据 ResolvedFrame 的 source_file + source_line 定位并读取源代码。
"""
import os
from pathlib import Path
from typing import Optional


class SourceResolver:
    """源文件定位器。

    根据 ResolvedFrame 的 source_file + source_line 定位并读取源代码。
    包含路径逃逸安全防护。

    Args:
        source_root: 源文件根目录 (通常为 git 仓库根目录)
    """

    def __init__(self, source_root: Path):
        self.source_root = Path(os.path.realpath(source_root))

    def read_source(self, file_path: str, line: int, context_lines: int = 10) -> str:
        """读取崩溃位置的源代码上下文。

        Args:
            file_path: 相对于 source_root 的文件路径
            line: 崩溃行号 (1-indexed)
            context_lines: 上下文行数 (前后各 N 行)

        Returns:
            带行号的源代码片段

        Raises:
            ValueError: 路径逃逸 source_root
        """
        full_path = Path(os.path.realpath(self.source_root / file_path))

        # Security: ensure path is within source_root
        if not str(full_path).startswith(str(self.source_root)):
            raise ValueError(
                f"Path escapes source root: {file_path} -> {full_path}"
            )

        if not full_path.exists():
            return f"// Source file not found: {file_path}"

        start = max(1, line - context_lines)
        end = line + context_lines + 1

        lines = []
        with open(full_path, "r") as f:
            for i, content in enumerate(f, 1):
                if start <= i < end:
                    marker = ">>>" if i == line else "   "
                    lines.append(f"{marker} {i:4d} {content.rstrip()}")
                if i >= end:
                    break

        return "\n".join(lines) if lines else f"// Line {line} not found in {file_path}"
