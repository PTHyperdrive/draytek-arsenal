"""Draytek "V3000" firmware container (Vigor 300B / 2960 / 3900).

These models predate the RTOS and ``enc_Image`` formats handled elsewhere in
this toolkit and use a plain-text checksum header in front of a ubinized UBI
image. Nothing in the container is encrypted.

The layout comes straight from Draytek's own GPL build script, which assembles
the image as::

    cat machine_type root.ubifs-ubinized  > unchecked.all
    md5sum unchecked.all                 -> checksum_md5
    mkcrc32 unchecked.all                -> checksum_crc32
    cat checksum_md5 checksum_crc32 unchecked.all > V300B.all

so on disk that is::

    0x00  32 bytes  lowercase hex MD5 of the payload
    0x20   1 byte   '\\n'
    0x21   8 bytes  lowercase hex CRC-32 of the payload
    0x29   1 byte   '\\n'
    0x2a   5 bytes  machine type, e.g. "V3000"
    0x2f   1 byte   '\\n'
    0x30   ...      ubinized UBI image

Both checksums cover ``data[0x2a:]`` -- the machine-type line *and* the UBI
image, not the UBI image alone.

Over-the-air ``.ota`` files are the same bytes with a 256-byte RSA-2048
signature prepended; the payload after that prefix is byte-identical to the
matching ``.all``.
"""

from __future__ import annotations

import hashlib
import re
import zlib
from dataclasses import dataclass
from typing import Optional

HEADER_SIZE = 0x30
MD5_OFFSET = 0x00
CRC_OFFSET = 0x21
MACHINE_OFFSET = 0x2A
PAYLOAD_OFFSET = MACHINE_OFFSET  # checksums cover the machine-type line too
UBI_OFFSET = HEADER_SIZE

OTA_SIGNATURE_SIZE = 256  # RSA-2048

_HEADER_RE = re.compile(rb"^[0-9a-f]{32}\n[0-9a-f]{8}\n[0-9A-Za-z]{5}\n")

# Machine-type tags, from the GPL build script's per-model blocks.
MACHINE_TYPES = {
    "V3000": ("Vigor 300B", "firmware (.all, keeps configuration)"),
    "V3010": ("Vigor 300B", "firmware (.rst, resets to factory defaults)"),
    "V3100": ("Vigor 300B", "firmware (.cv3)"),
    "V3001": ("Vigor 300B", "bootloader (u-boot)"),
    "X2000": ("Vigor 2960", "firmware (.all, keeps configuration)"),
    "X2010": ("Vigor 2960", "firmware (.rst, resets to factory defaults)"),
    "X2100": ("Vigor 2960", "firmware (.cx2)"),
    "X2001": ("Vigor 2960", "bootloader (u-boot)"),
    "39000": ("Vigor 3900", "firmware (.all, keeps configuration)"),
    "39010": ("Vigor 3900", "firmware (.rst, resets to factory defaults)"),
    "39001": ("Vigor 3900", "bootloader (u-boot)"),
}


class V3000Error(Exception):
    pass


@dataclass
class V3000Image:
    machine_type: str
    stored_md5: str
    stored_crc32: str
    actual_md5: str
    actual_crc32: str
    payload: bytes          # machine-type line + UBI image (what the checksums cover)
    ubi: bytes              # the ubinized UBI image alone
    ota_signature: Optional[bytes] = None

    @property
    def md5_ok(self) -> bool:
        return self.stored_md5 == self.actual_md5

    @property
    def crc_ok(self) -> bool:
        return self.stored_crc32 == self.actual_crc32

    @property
    def valid(self) -> bool:
        return self.md5_ok and self.crc_ok

    @property
    def is_ota(self) -> bool:
        return self.ota_signature is not None

    @property
    def model(self) -> str:
        return MACHINE_TYPES.get(self.machine_type, ("unknown", ""))[0]

    @property
    def kind(self) -> str:
        return MACHINE_TYPES.get(self.machine_type, ("", "unknown"))[1]


def looks_like_v3000(data: bytes) -> bool:
    """True if ``data`` starts with a V3000 header, with or without an OTA prefix."""
    return bool(_HEADER_RE.match(data[:HEADER_SIZE])) or bool(
        _HEADER_RE.match(data[OTA_SIGNATURE_SIZE:OTA_SIGNATURE_SIZE + HEADER_SIZE])
    )


def parse(data: bytes) -> V3000Image:
    """Parse a ``.all`` / ``.rst`` / ``.cv3`` / ``.ota`` container."""
    signature = None
    if not _HEADER_RE.match(data[:HEADER_SIZE]):
        if _HEADER_RE.match(data[OTA_SIGNATURE_SIZE:OTA_SIGNATURE_SIZE + HEADER_SIZE]):
            signature = data[:OTA_SIGNATURE_SIZE]
            data = data[OTA_SIGNATURE_SIZE:]
        else:
            raise V3000Error("not a Draytek V3000 container (bad header)")

    stored_md5 = data[MD5_OFFSET:MD5_OFFSET + 32].decode("ascii")
    stored_crc = data[CRC_OFFSET:CRC_OFFSET + 8].decode("ascii")
    machine = data[MACHINE_OFFSET:MACHINE_OFFSET + 5].decode("ascii")

    payload = data[PAYLOAD_OFFSET:]
    ubi = data[UBI_OFFSET:]

    return V3000Image(
        machine_type=machine,
        stored_md5=stored_md5,
        stored_crc32=stored_crc,
        actual_md5=hashlib.md5(payload).hexdigest(),
        actual_crc32=f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}",
        payload=payload,
        ubi=ubi,
        ota_signature=signature,
    )


def build(ubi_image: bytes, machine_type: str = "V3000") -> bytes:
    """Wrap a ubinized UBI image in a V3000 container with correct checksums.

    This is the inverse of :func:`parse` and mirrors the GPL build script, so a
    repacked image passes the same validation the stock updater applies.
    """
    if len(machine_type) != 5:
        raise V3000Error(f"machine type must be 5 characters, got {machine_type!r}")
    payload = machine_type.encode("ascii") + b"\n" + ubi_image
    md5 = hashlib.md5(payload).hexdigest()
    crc = f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}"
    return md5.encode() + b"\n" + crc.encode() + b"\n" + payload
