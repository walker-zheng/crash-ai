"""ELF core dump reader — based on pyelftools for CrashContext extraction."""
from pathlib import Path

from src.models.crash import CrashContext


class ELFReader:
    """ELF core dump parser (Phase 1: stub, GDB-driven symbol resolution)."""

    MAX_SIZE = 4 * 1024 * 1024 * 1024

    def __init__(self, filepath: Path):
        self.filepath = filepath

    def read(self) -> CrashContext:
        """Parse ELF core dump header only; full context via GDB in symbol layer.

        Raises:
            NotImplementedError: Phase 1 uses GDB for full core analysis. This
                stub validates the ELF header only.
        """
        raise NotImplementedError(
            "ELFReader.read() — Phase 1 uses GDB for full core analysis. "
            "This stub validates ELF header only."
        )
