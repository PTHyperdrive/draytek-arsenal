"""Tests for the pure-Python LZ4 block decoder.

The unit tests are self-contained. When the compiled ``lz4`` package is
installed the decoder is additionally differential-tested against it, which is
what actually pins the format down. The integration test only runs when a real
image is pointed at by ``DRAYTEK_TEST_FIRMWARE``, since firmware cannot be
redistributed with the source:

    DRAYTEK_TEST_FIRMWARE=/path/to/v2862_39912_STD_001.all pytest
"""

from __future__ import annotations

import os
import random

import pytest

from draytek_arsenal import lz4_block
from draytek_arsenal.compression import Lz4

try:
    import lz4.block as _clz4
except ImportError:
    _clz4 = None

needs_clz4 = pytest.mark.skipif(_clz4 is None, reason="the lz4 package is not installed")


# --------------------------------------------------------------------------
# Hand-built blocks
# --------------------------------------------------------------------------

def test_literals_only():
    # One token, 8 literals, no match: the final sequence of every block.
    block = bytes([0x80]) + b"ABCDEFGH"
    assert lz4_block.decompress(block) == b"ABCDEFGH"


def test_empty_block():
    assert lz4_block.decompress(b"") == b""


def test_simple_match():
    # 8 literals, then offset 8 / length 4 repeats them from the start.
    block = bytes([0x80]) + b"ABCDEFGH" + bytes([0x08, 0x00])
    assert lz4_block.decompress(block) == b"ABCDEFGHABCD"


def test_overlapping_match_is_run_length():
    # Offset 1 with length 6 must replay the byte as it is produced, not copy
    # a 6-byte window that does not exist yet.
    block = bytes([0x82]) + b"ABCDEFGH" + bytes([0x01, 0x00])
    assert lz4_block.decompress(block) == b"ABCDEFGH" + b"H" * 6


def test_extended_literal_length():
    payload = bytes(range(256))  # 256 literals = 15 + one extension byte of 241
    block = bytes([0xF0, 0xF1]) + payload
    assert lz4_block.decompress(block) == payload


def test_chained_literal_length_extension():
    # A 0xFF extension byte means "keep reading": 15 + 255 + 12 literals.
    payload = bytes(range(256)) * 2
    payload = payload[:15 + 255 + 12]
    block = bytes([0xF0, 0xFF, 0x0C]) + payload
    assert lz4_block.decompress(block) == payload


def test_extended_match_length():
    # match length 15 + 255 + 4 (+ MIN_MATCH) replayed from offset 1.
    block = bytes([0x1F, 0x41, 0x01, 0x00, 0xFF, 0x04])
    assert lz4_block.decompress(block) == b"A" * (1 + 15 + 255 + 4 + 4)


def test_expected_size_is_enforced():
    block = bytes([0x80]) + b"ABCDEFGH"
    assert lz4_block.decompress(block, expected_size=8) == b"ABCDEFGH"
    with pytest.raises(lz4_block.Lz4Error):
        lz4_block.decompress(block, expected_size=9)


@pytest.mark.parametrize("block, reason", [
    (bytes([0x80]) + b"ABCDEFGH" + bytes([0x00, 0x00]), "zero offset"),
    (bytes([0x40]) + b"ABCD" + bytes([0x10, 0x00]), "offset before start"),
    (bytes([0xF0]), "truncated length extension"),
    (bytes([0x80]) + b"ABC", "literal run past end"),
    (bytes([0x80]) + b"ABCDEFGH" + bytes([0x08]), "truncated offset"),
])
def test_corrupt_blocks_raise(block, reason):
    with pytest.raises(lz4_block.Lz4Error):
        lz4_block.decompress(block)


# --------------------------------------------------------------------------
# Differential against the C implementation
# --------------------------------------------------------------------------

def _corpora():
    rnd = random.Random(0xD2A7)
    return {
        "empty": b"",
        "incompressible": bytes(rnd.getrandbits(8) for _ in range(4096)),
        "runs": b"\x00" * 5000 + b"\xff" * 300,
        "repetitive": (b"DrayTek Vigor " * 400),
        "mips_like": bytes([0x27, 0xBD, 0xFF, 0xE0] * 2048),
        "mixed": bytes(rnd.getrandbits(8) for _ in range(64)) * 64,
        "full_block": bytes(rnd.choice(b"abcd") for _ in range(0x10000)),
    }


@needs_clz4
@pytest.mark.parametrize("name", sorted(_corpora()))
def test_matches_c_implementation(name):
    data = _corpora()[name]
    block = _clz4.compress(data, store_size=False)
    assert lz4_block.decompress(block, expected_size=len(data)) == data


@needs_clz4
def test_matches_c_implementation_at_high_compression():
    data = _corpora()["repetitive"]
    block = _clz4.compress(data, mode="high_compression", compression=12, store_size=False)
    assert lz4_block.decompress(block) == data


@needs_clz4
def test_container_round_trip_through_pure_decoder():
    """Lz4.compress writes the container; the pure decoder must read it back."""
    data = bytes(random.Random(7).choice(b"abcdef") for _ in range(0x30000))
    container = Lz4().compress(data)
    assert container[:4] == Lz4.magic

    offset, out = 4, b""
    while offset < len(container):
        size = int.from_bytes(container[offset:offset + 4], "little")
        offset += 4
        out += lz4_block.decompress(container[offset:offset + size])
        offset += size
    assert out == data


# --------------------------------------------------------------------------
# Integration
# --------------------------------------------------------------------------

@pytest.mark.skipif(
    not os.environ.get("DRAYTEK_TEST_FIRMWARE"),
    reason="set DRAYTEK_TEST_FIRMWARE to a real image to run this",
)
def test_real_firmware_sections_match_c_implementation():
    """Decode every LZ4 block in a real image both ways and compare."""
    data = open(os.environ["DRAYTEK_TEST_FIRMWARE"], "rb").read()

    blocks = 0
    start = data.find(Lz4.magic)
    assert start >= 0, "no DrayTek LZ4 container found in the image"

    offset = start + 4
    while offset + 4 <= len(data):
        size = int.from_bytes(data[offset:offset + 4], "little")
        if size == 0 or size > 2 * Lz4.max_decompressed_block_size:
            break
        offset += 4
        block = data[offset:offset + size]
        pure = lz4_block.decompress(block)
        if _clz4 is not None:
            assert pure == _clz4.decompress(
                block, uncompressed_size=Lz4.max_decompressed_block_size
            )
        assert len(pure) <= Lz4.max_decompressed_block_size
        offset += size
        blocks += 1

    assert blocks > 0
