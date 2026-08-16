"""Tests for the V3000 container, UBI reader and LZO decoder.

The unit tests are self-contained. The integration test only runs when a real
image is pointed at by ``DRAYTEK_TEST_FIRMWARE``, since firmware cannot be
redistributed with the source:

    DRAYTEK_TEST_FIRMWARE=/path/to/Vigor300B_v1.5.1.all pytest
"""

from __future__ import annotations

import hashlib
import os
import zlib

import pytest

from draytek_arsenal import lzo1x, ubi, ubifs, v3000


# --------------------------------------------------------------------------
# V3000 container
# --------------------------------------------------------------------------

def _fake_ubi(pebs: int = 2, peb_size: int = 0x20000) -> bytes:
    """Build a minimal but structurally valid UBI image."""
    out = bytearray()
    for i in range(pebs):
        ec = bytearray(64)
        ec[0:4] = b"UBI#"
        ec[4] = 1
        ec[8:16] = (0).to_bytes(8, "big")
        ec[16:20] = (0x200).to_bytes(4, "big")   # vid_hdr_offset
        ec[20:24] = (0x800).to_bytes(4, "big")   # data_offset
        ec[24:28] = (0xDEADBEEF).to_bytes(4, "big")
        ec[28:32] = b"\x00\x00\x00\x00"
        ec[32:41] = b"9.9.9_TST"
        ec[60:64] = ubi.ubi_crc32(bytes(ec[:60])).to_bytes(4, "big")

        peb = bytearray(b"\xff" * peb_size)
        peb[0:64] = ec

        vid = bytearray(64)
        vid[0:4] = b"UBI!"
        vid[4] = 1
        vid[5] = 1                                # dynamic
        vid[8:12] = (0).to_bytes(4, "big")        # vol_id
        vid[12:16] = (i).to_bytes(4, "big")       # lnum
        vid[40:48] = (i + 1).to_bytes(8, "big")   # sqnum
        vid[60:64] = ubi.ubi_crc32(bytes(vid[:60])).to_bytes(4, "big")
        peb[0x200:0x240] = vid

        peb[0x800:0x808] = b"PAYLOAD" + bytes([i])
        out.extend(peb)
    return bytes(out)


def test_build_then_parse_round_trips():
    image = _fake_ubi()
    blob = v3000.build(image, "V3000")

    parsed = v3000.parse(blob)
    assert parsed.machine_type == "V3000"
    assert parsed.model == "Vigor 300B"
    assert parsed.valid
    assert parsed.ubi == image
    assert not parsed.is_ota


def test_header_layout_matches_gpl_build_script():
    """Checksums must cover the machine-type line, not just the UBI image."""
    image = _fake_ubi(pebs=1)
    blob = v3000.build(image, "V3000")

    assert blob[0x20:0x21] == b"\n"
    assert blob[0x29:0x2a] == b"\n"
    assert blob[0x2a:0x2f] == b"V3000"
    assert blob[0x2f:0x30] == b"\n"

    payload = blob[0x2a:]
    assert blob[0x00:0x20].decode() == hashlib.md5(payload).hexdigest()
    assert blob[0x21:0x29].decode() == f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}"

    # Hashing the UBI image alone must NOT reproduce the stored digest.
    assert blob[0x00:0x20].decode() != hashlib.md5(blob[0x30:]).hexdigest()


def test_corruption_is_detected():
    blob = bytearray(v3000.build(_fake_ubi(pebs=1), "V3000"))
    blob[0x40] ^= 0xFF
    parsed = v3000.parse(bytes(blob))
    assert not parsed.valid
    assert not parsed.md5_ok
    assert not parsed.crc_ok


def test_ota_signature_prefix_is_detected_and_stripped():
    inner = v3000.build(_fake_ubi(pebs=1), "V3000")
    signature = bytes(range(256))
    parsed = v3000.parse(signature + inner)

    assert parsed.is_ota
    assert parsed.ota_signature == signature
    assert parsed.valid
    # The payload after the signature is byte-identical to the .all form.
    assert v3000.build(parsed.ubi, parsed.machine_type) == inner


def test_machine_types_map_to_models():
    assert v3000.MACHINE_TYPES["V3010"][0] == "Vigor 300B"
    assert "resets to factory" in v3000.MACHINE_TYPES["V3010"][1]
    assert v3000.MACHINE_TYPES["X2000"][0] == "Vigor 2960"
    assert v3000.MACHINE_TYPES["39000"][0] == "Vigor 3900"


def test_rejects_non_v3000():
    with pytest.raises(v3000.V3000Error):
        v3000.parse(b"\x00" * 4096)
    assert not v3000.looks_like_v3000(b"\x00" * 4096)


def test_build_rejects_bad_machine_type():
    with pytest.raises(v3000.V3000Error):
        v3000.build(_fake_ubi(pebs=1), "TOOLONG")


# --------------------------------------------------------------------------
# UBI
# --------------------------------------------------------------------------

def test_ubi_parses_synthetic_image():
    img = ubi.parse(_fake_ubi(pebs=3))
    assert img.peb_size == 0x20000
    assert img.leb_size == 0x20000 - 0x800
    assert img.total_pebs == 3
    assert img.ec_header.crc_ok
    assert img.ec_header.embedded_string == "9.9.9_TST"
    assert 0 in img.volumes
    assert img.volumes[0].data().startswith(b"PAYLOAD\x00")


def test_ubi_crc32_is_kernel_flavoured():
    # Kernel crc32 seeds at 0xFFFFFFFF with no final inversion, which is the
    # standard CRC-32 inverted.
    data = b"draytek"
    assert ubi.ubi_crc32(data) == (zlib.crc32(data) ^ 0xFFFFFFFF) & 0xFFFFFFFF


# --------------------------------------------------------------------------
# LZO1X
# --------------------------------------------------------------------------

def test_lzo_literal_only_stream():
    # First byte > 17 encodes a leading literal run of (b - 17) bytes,
    # then the end-of-stream marker (0x11, 0x00, 0x00).
    payload = b"draytek-arsenal!"
    stream = bytes([17 + len(payload)]) + payload + b"\x11\x00\x00"
    assert lzo1x.decompress(stream) == payload


def test_lzo_empty_input():
    assert lzo1x.decompress(b"") == b""


def test_lzo_rejects_truncated_input():
    with pytest.raises(lzo1x.LzoError):
        lzo1x.decompress(bytes([17 + 50]) + b"short")


def test_lzo_size_mismatch_raises():
    payload = b"abcd"
    stream = bytes([17 + len(payload)]) + payload + b"\x11\x00\x00"
    with pytest.raises(lzo1x.LzoError):
        lzo1x.decompress(stream, expected_size=999)


# --------------------------------------------------------------------------
# Integration (needs a real image)
# --------------------------------------------------------------------------

FIRMWARE = os.environ.get("DRAYTEK_TEST_FIRMWARE")


@pytest.mark.skipif(not FIRMWARE, reason="set DRAYTEK_TEST_FIRMWARE to a real image")
def test_real_firmware_end_to_end():
    with open(FIRMWARE, "rb") as fh:
        data = fh.read()

    img = v3000.parse(data)
    assert img.valid, "stock image must pass its own MD5/CRC32"

    # Repacking the untouched UBI image must reproduce the original bytes.
    rebuilt = v3000.build(img.ubi, img.machine_type)
    expected = data[v3000.OTA_SIGNATURE_SIZE:] if img.is_ota else data
    assert rebuilt == expected

    ubi_img = ubi.parse(img.ubi)
    rootfs = next(v for v in ubi_img.data_volumes if v.name == "rootfs")
    assert not rootfs.verify()

    fs = ubifs.parse(rootfs.data(), ubi_img.leb_size)
    assert fs.stats.bad_crc == 0
    assert fs.sb is not None
    assert ubifs.ROOT_INO in fs.inodes

    # Every regular file must reconstruct to exactly its inode size.
    checked = 0
    for inum, ino in fs.inodes.items():
        if ino.is_reg and ino.size:
            assert len(fs.file_data(ino)) == ino.size
            checked += 1
    assert checked > 100
