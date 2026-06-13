"""Tests for ELFReader — ELF core dump reader (Phase 1 stub)."""
import tempfile
from pathlib import Path

import pytest

from src.input.elf_reader import ELFReader


class TestELFReader:
    """ELF reader stub tests."""

    def test_read_raises_not_implemented(self):
        """ELFReader.read() raises NotImplementedError in Phase 1."""
        tmp = tempfile.NamedTemporaryFile(suffix=".core", delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        try:
            tmp_path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20)
            reader = ELFReader(tmp_path)
            with pytest.raises(NotImplementedError):
                reader.read()
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_reader_accepts_valid_path(self):
        """ELFReader initialises with a valid path without error."""
        tmp = tempfile.NamedTemporaryFile(suffix=".core", delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        try:
            tmp_path.write_bytes(b"\x7fELF" + b"\x00" * 20)
            reader = ELFReader(tmp_path)
            assert reader.filepath == tmp_path
        finally:
            tmp_path.unlink(missing_ok=True)
