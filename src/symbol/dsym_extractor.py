"""dSYM 符号提取器 — llvm-dwarfdump --debug-info (macOS)。"""
import subprocess
from pathlib import Path
from src.errors import InputError


def extract_dsym_symbols(dsym_path: Path, output_dir: Path) -> Path:
    """从 dSYM bundle 提取调试符号。

    Phase 1: 提供基础实现框架。
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            [
                "llvm-dwarfdump", "--debug-info",
                str(dsym_path),
                "-o", str(output_dir / "debug_info.txt"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except FileNotFoundError:
        raise InputError(
            "llvm-dwarfdump not found. Install LLVM tools."
        )

    return output_dir
