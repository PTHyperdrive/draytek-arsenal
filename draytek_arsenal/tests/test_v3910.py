"""Tests for the 3910-family (ARM64 Linux) container.

Unit tests are self-contained: they build minimal but structurally valid
images. The integration test only runs when a real image is pointed at by
``DRAYTEK_TEST_V3910``, since firmware cannot be redistributed with the
source:

    DRAYTEK_TEST_V3910=/path/to/v3910_3971.all pytest
"""

from __future__ import annotations

import os
import struct

import pytest

from draytek_arsenal import v3910


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------

def _arm64_image(text_offset=0x80000, image_size=0x1000, flags=0xA) -> bytes:
    """A 64-byte ARM64 Image header: magic "ARM\\x64" lives at +0x38."""
    hdr = bytearray(0x40)
    struct.pack_into("<II", hdr, 0, 0x91005A4D, 0x14263FFF)   # code0, code1
    struct.pack_into("<QQQ", hdr, 8, text_offset, image_size, flags)
    hdr[0x38:0x3C] = v3910.ARM64_MAGIC
    return bytes(hdr)


def _plain_image(version=b"3.9.7.1_RC1", pad=0x20000) -> bytes:
    out = bytearray(b"\x00" * pad)
    out[:4] = bytes.fromhex("06020106")
    out[0x28:0x28 + len(version)] = version
    out[0x10000:0x10000 + 0x40] = _arm64_image()
    return bytes(out)


def _record(name: bytes, payload: bytes) -> bytes:
    return (struct.pack("<I", len(name)) + name
            + struct.pack("<I", len(payload)) + payload)


def _encrypted_image(version=b"4.3.5.1_RC3") -> bytes:
    out = bytearray(b"\x00" * 0x40)
    out[:4] = b"6216"
    out[0x0D:0x0D + len(version)] = version
    out += _record(b"nonce", b"ZssawjSLs95Q")
    out += b"\x00" * 16
    out += _record(b"vmlinuz.enc", b"\xAA" * 4096)
    out += b"\x00" * 16
    out += _record(b"uver", b"17")
    return bytes(out).ljust(0x20000, b"\x00")


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def test_detects_plain_image():
    assert v3910.looks_like_v3910(_plain_image())


def test_rejects_foreign_images():
    assert not v3910.looks_like_v3910(b"\x00" * 0x20000)
    assert not v3910.looks_like_v3910(b"")
    # An RTOS image starts with a big-endian section size, not our magic.
    assert not v3910.looks_like_v3910(b"\x00\xFC\x5D\x54" + b"\x00" * 0x20000)


def test_parse_rejects_unknown_header():
    with pytest.raises(ValueError):
        v3910.parse(b"NOPE" + b"\x00" * 0x20000)


# --------------------------------------------------------------------------
# Plain images
# --------------------------------------------------------------------------

def test_plain_image_fields():
    img = v3910.parse(_plain_image())
    assert img.kind == v3910.PLAIN
    assert img.version == "3.9.7.1_RC1"
    assert img.bootable
    assert img.kernel.offset == 0x10000
    assert img.kernel.text_offset == 0x80000
    assert img.kernel.little_endian


def test_kernel_bytes_run_to_end_of_image():
    """image_size is a runtime footprint, so the carve must not use it."""
    data = _plain_image()
    img = v3910.parse(data)
    assert img.kernel_bytes() == data[0x10000:]
    assert len(img.kernel_bytes()) != img.kernel.image_size


def test_big_endian_flag_is_read():
    out = bytearray(_plain_image())
    out[0x10000:0x10000 + 0x40] = _arm64_image(flags=0xB)   # bit0 set = BE
    assert not v3910.parse(bytes(out)).kernel.little_endian


def test_device_trees_are_validated_not_just_matched():
    """A bare d00dfeed with a nonsense header must not count as a DTB."""
    out = bytearray(_plain_image())
    out[0x18000:0x18004] = v3910.FDT_MAGIC          # magic only, junk after
    assert v3910.parse(bytes(out)).dtbs == []


def test_real_device_tree_is_found():
    out = bytearray(_plain_image())
    total = 0x40
    dtb = bytearray(total)
    struct.pack_into(">7I", dtb, 0,
                     int.from_bytes(v3910.FDT_MAGIC, "big"), total,
                     0x38, 0x3C, 0x28, 17, 16)
    out[0x18000:0x18000 + total] = dtb
    found = v3910.parse(bytes(out)).dtbs
    assert len(found) == 1 and found[0].offset == 0x18000 and found[0].size == total


# --------------------------------------------------------------------------
# Encrypted images
# --------------------------------------------------------------------------

def test_encrypted_image_members_and_nonce():
    img = v3910.parse(_encrypted_image())
    assert img.kind == v3910.ENCRYPTED
    assert img.version == "4.3.5.1_RC3"
    assert not img.bootable
    assert img.nonce == b"ZssawjSLs95Q"
    names = [m.name for m in img.members]
    assert "vmlinuz.enc" in names and "uver" in names
    assert "nonce" not in names          # consumed, not listed as a member


def test_encrypted_members_flag_themselves():
    img = v3910.parse(_encrypted_image())
    by_name = {m.name: m for m in img.members}
    assert by_name["vmlinuz.enc"].encrypted
    assert not by_name["uver"].encrypted
    assert by_name["vmlinuz.enc"].size == 4096


def test_kernel_bytes_refuses_an_encrypted_image():
    with pytest.raises(ValueError):
        v3910.parse(_encrypted_image()).kernel_bytes()


# --------------------------------------------------------------------------
# QEMU invocation
# --------------------------------------------------------------------------

def test_qemu_argv_shape():
    argv = v3910.qemu_argv("Image", memory=1024, cpu="max")
    assert argv[0] == "qemu-system-aarch64"
    assert argv[argv.index("-kernel") + 1] == "Image"
    assert argv[argv.index("-m") + 1] == "1024"
    assert argv[argv.index("-cpu") + 1] == "max"
    assert argv[argv.index("-M") + 1] == "virt"
    # earlycon is what produces output before the console driver probes
    assert "earlycon" in argv[argv.index("-append") + 1]
    # a board DTB would describe hardware virt does not have
    assert "-dtb" not in argv


# --------------------------------------------------------------------------
# Integration
# --------------------------------------------------------------------------

@pytest.mark.skipif(not os.environ.get("DRAYTEK_TEST_V3910"),
                    reason="set DRAYTEK_TEST_V3910 to a real image to run this")
def test_real_image():
    data = open(os.environ["DRAYTEK_TEST_V3910"], "rb").read()
    assert v3910.looks_like_v3910(data)
    img = v3910.parse(data)
    if img.kind == v3910.PLAIN:
        assert img.bootable
        assert img.kernel.text_offset == 0x80000
        assert img.dtbs, "a real image carries board device trees"
        assert len(img.kernel_bytes()) > 1 << 20
    else:
        assert len(img.nonce) == 12
        assert any(m.encrypted for m in img.members)
