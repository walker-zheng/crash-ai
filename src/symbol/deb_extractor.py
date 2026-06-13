"""DEB 包调试符号提取器 — dpkg-deb -x。"""
import subprocess
from pathlib import Path
from src.errors import InputError


def extract_deb_symbols(deb_path: Path, output_dir: Path) -> Path:
    """从 DEB 包提取调试符号。

    Phase 1: 提供基础实现框架。
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            ["dpkg-deb", "-x", str(deb_path), str(output_dir)],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except FileNotFoundError:
        raise InputError(
            "dpkg-deb not found. Are you running on a Debian-based system?"
        )

    return output_dir
