"""Minidump-to-ELF converter — based on google-breakpad minidump-2-core."""
import subprocess
from pathlib import Path

from src.errors import InputError


def convert_minidump_to_elf(minidump_path: Path, output_dir: Path) -> Path:
    """Convert a Minidump to an ELF core file using google-breakpad.

    Phase 1: Checks minidump-2-core availability and gives a clear error if
    the tool is not installed.

    Args:
        minidump_path: Path to the .dmp minidump file.
        output_dir: Directory for the converted .core file.

    Returns:
        Path to the converted ELF core file.

    Raises:
        InputError: if minidump-2-core is not found or conversion fails.
    """
    try:
        subprocess.run(
            ["which", "minidump-2-core"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        raise InputError(
            "minidump-2-core not found. Install google-breakpad: "
            "https://github.com/google/breakpad"
        )

    output_path = output_dir / f"{minidump_path.stem}.core"
    result = subprocess.run(
        ["minidump-2-core", str(minidump_path), str(output_path)],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise InputError(f"Minidump conversion failed: {result.stderr}")
    return output_path
