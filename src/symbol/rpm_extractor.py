"""RPM 包调试符号提取器 — rpm2cpio | cpio -idmv。"""
import subprocess
from pathlib import Path
from src.errors import InputError


def extract_rpm_symbols(rpm_path: Path, output_dir: Path) -> Path:
    """从 RPM 包提取调试符号。

    Phase 1: 提供基础实现框架。完整实现需要 rpm2cpio + cpio 工具。
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        rpm2cpio = subprocess.Popen(
            ["rpm2cpio", str(rpm_path)], stdout=subprocess.PIPE
        )
        subprocess.run(
            ["cpio", "-idmv"],
            stdin=rpm2cpio.stdout,
            cwd=str(output_dir),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        rpm2cpio.stdout.close()
        rpm2cpio.wait()
    except FileNotFoundError:
        raise InputError(
            "rpm2cpio or cpio not found. Install rpm2cpio package."
        )

    return output_dir
