"""Core dump format detection — magic bytes + ELF e_type validation."""
import os
from pathlib import Path

from src.errors import InputError


ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce",  # 32-bit big-endian
    b"\xfe\xed\xfa\xcf",  # 64-bit big-endian
    b"\xce\xfa\xed\xfe",  # 32-bit little-endian
    b"\xcf\xfa\xed\xfe",  # 64-bit little-endian
)
MINIDUMP_MAGIC = b"MDMP"

MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024  # 4GB


def detect_format(filepath: Path) -> str:
    """Detect core dump file format, returning 'elf' / 'macho' / 'minidump'.

    Raises:
        InputError: if the file is not found, too large, too small, or of
            unknown format.
    """
    if not filepath.exists():
        raise InputError(f"File not found: {filepath}")

    file_size = os.path.getsize(filepath)
    if file_size > MAX_FILE_SIZE:
        raise InputError(f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})")

    if file_size < 4:
        raise InputError(
            f"File too small: {file_size} bytes (minimum 4 bytes for magic)"
        )

    with open(filepath, "rb") as f:
        magic = f.read(4)

    if magic[:4] == ELF_MAGIC:
        return "elf"
    elif magic in MACHO_MAGICS:
        return "macho"
    elif magic == MINIDUMP_MAGIC:
        return "minidump"
    else:
        raise InputError(
            f"Unknown file format: magic={magic.hex()} "
            f"Expected ELF, Mach-O, or Minidump"
        )
