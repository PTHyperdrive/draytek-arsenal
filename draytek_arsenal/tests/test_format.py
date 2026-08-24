"""Tests for the image MD5 trailer and for PFS extraction staging.

The PFS test is a regression test for extraction on Windows: PFSExtractor
takes a path, and Windows will not reopen a still-open NamedTemporaryFile by
name, so staging the archive has to go through a temp *directory*.
"""

from __future__ import annotations

import hashlib
import os
import struct

import pytest

from draytek_arsenal.format import IMAGE_MD5_TAG, verify_image_md5

try:
    from draytek_arsenal.commands.extract import ExtractCommand
    from draytek_arsenal.fs import PFSExtractor
except ImportError as exc:  # optional third-party dependency missing
    ExtractCommand = None
    _extract_import_error = exc


# --------------------------------------------------------------------------
# Image MD5 trailer
# --------------------------------------------------------------------------

def _tagged(body: bytes, digest: str | None = None) -> bytes:
    digest = digest if digest is not None else hashlib.md5(body).hexdigest()
    return body + IMAGE_MD5_TAG + digest.encode()


def test_valid_trailer():
    body = b"firmware" * 64
    ok, claimed, actual = verify_image_md5(_tagged(body))
    assert ok
    assert claimed == actual == hashlib.md5(body).hexdigest()


def test_corrupt_body_is_detected():
    body = bytearray(b"firmware" * 64)
    image = bytearray(_tagged(bytes(body)))
    image[10] ^= 0xFF  # flip a bit inside the covered region
    ok, claimed, actual = verify_image_md5(bytes(image))
    assert not ok
    assert claimed != actual


def test_trailing_bytes_after_the_tag_are_not_covered():
    """The digest covers everything *before* the tag, and nothing after it."""
    body = b"firmware" * 64
    assert verify_image_md5(_tagged(body) + b"\x00" * 16)[0]


def test_last_trailer_wins():
    """rfind: an image whose payload happens to contain the tag still checks."""
    inner = b"junk" + IMAGE_MD5_TAG + b"0" * 32
    assert verify_image_md5(_tagged(inner))[0]


def test_missing_trailer_returns_none():
    assert verify_image_md5(b"no trailer here") is None


# --------------------------------------------------------------------------
# PFS extraction staging
# --------------------------------------------------------------------------

NAME_FIELD = 32


def _pfs(files: dict[str, bytes]) -> bytes:
    """Build a minimal but structurally valid PFS/1.0 archive."""
    header = b"PFS/1.0".ljust(14, b"\x00") + struct.pack("<H", len(files))

    nodes, bodies, offset = b"", b"", 0
    for i, (name, body) in enumerate(files.items()):
        nodes += name.encode().ljust(NAME_FIELD, b"\x00")
        nodes += struct.pack("<III", i + 1, offset, len(body))
        bodies += body
        offset += len(body)

    return header + nodes + bodies


@pytest.mark.skipif(ExtractCommand is None, reason="extract command dependencies missing")
def test_extract_pfs_writes_every_file(tmp_path):
    files = {
        "V2000/index.htm": b"<html>hello</html>",
        "V2000/SYSINFO.TXT": b"Vigor2862 Series\nEnglish\n",
        "V2000/sub/deep.bin": bytes(range(256)),
    }
    out = tmp_path / "www"

    # Must not raise: on Windows the old NamedTemporaryFile staging died here
    # with PermissionError [Errno 13].
    ExtractCommand._extract_pfs(_pfs(files), str(out), PFSExtractor())

    for name, body in files.items():
        written = out / name
        assert written.is_file(), f"{name} was not extracted"
        assert written.read_bytes() == body


@pytest.mark.skipif(ExtractCommand is None, reason="extract command dependencies missing")
def test_extract_pfs_creates_missing_output_dir(tmp_path):
    out = tmp_path / "does" / "not" / "exist"
    ExtractCommand._extract_pfs(_pfs({"a.txt": b"x"}), str(out), PFSExtractor())
    assert (out / "a.txt").read_bytes() == b"x"


@pytest.mark.skipif(ExtractCommand is None, reason="extract command dependencies missing")
def test_extract_pfs_leaves_no_temp_files_behind(tmp_path):
    """The staging directory is removed even though a file was created in it."""
    import tempfile

    before = set(os.listdir(tempfile.gettempdir()))
    ExtractCommand._extract_pfs(_pfs({"a.txt": b"x"}), str(tmp_path / "o"), PFSExtractor())
    leaked = set(os.listdir(tempfile.gettempdir())) - before
    assert not leaked, f"temp entries left behind: {leaked}"
