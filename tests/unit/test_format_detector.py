"""Tests for format_detector — core dump format detection."""
import os
import tempfile
from pathlib import Path

import pytest

from src.errors import InputError
from src.input.format_detector import detect_format


class TestFormatDetector:
    """Core dump format detection tests."""

    def test_detect_elf_core_from_magic(self):
        """ELF magic (\\x7fELF) with ET_CORE returns 'elf'."""
        content = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        # e_type at offset 16 (2 bytes, little-endian): ET_CORE = 4
        content[16:18] = b"\x04\x00"
        tmp = tempfile.NamedTemporaryFile(suffix=".core", delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        try:
            tmp_path.write_bytes(bytes(content))
            result = detect_format(tmp_path)
            assert result == "elf"
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_detect_elf_non_core_rejected(self):
        """ELF with e_type != ET_CORE still detected as 'elf'."""
        content = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        # e_type = 2 (ET_EXEC), not 4 (ET_CORE)
        content[16:18] = b"\x02\x00"
        tmp = tempfile.NamedTemporaryFile(suffix=".elf", delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        try:
            tmp_path.write_bytes(bytes(content))
            result = detect_format(tmp_path)
            assert result == "elf"
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_unknown_format_raises(self):
        """Unknown format raises InputError."""
        tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        try:
            tmp_path.write_bytes(b"not a valid format\x00\x00")
            with pytest.raises(InputError):
                detect_format(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_file_too_large_raises(self):
        """File over 4GB raises InputError."""
        tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        try:
            tmp_path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
            original_getsize = os.path.getsize
            os.path.getsize = lambda p: 5 * 1024 * 1024 * 1024  # 5GB
            with pytest.raises(InputError, match="too large"):
                detect_format(tmp_path)
        finally:
            os.path.getsize = original_getsize
            tmp_path.unlink(missing_ok=True)

    def test_nonexistent_file_raises(self):
        """Non-existent file raises InputError."""
        with pytest.raises(InputError, match="not found"):
            detect_format(Path("/tmp/nonexistent_core_file_xyzzy"))

    def test_file_smaller_than_4_bytes(self):
        """File smaller than 4 bytes raises InputError."""
        tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        tmp_path = Path(tmp.name)
        tmp.close()
        try:
            tmp_path.write_bytes(b"ELF")
            with pytest.raises(InputError):
                detect_format(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
