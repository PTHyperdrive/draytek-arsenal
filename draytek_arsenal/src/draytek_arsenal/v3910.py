"""Vigor 3910 / 2962 / 3912 family: ARM64 Linux images.

These models are not the MIPS RTOS container and not the V3000 UBI container.
They are a DrayTek header followed by a Marvell/Cavium OCTEON TX boot chain:
ATF and U-Boot, a pile of board device trees, an ARM64 Linux ``Image``, and a
root filesystem. DrayOS itself runs as a *process* on that Linux rather than
being the kernel.

Two generations share this family, under two container headers:

``plain``
    3.9.x and earlier. Everything is in the clear. The kernel carries its
    root filesystem as an embedded initramfs, which is what makes these
    directly bootable under ``qemu-system-aarch64 -M virt``.

``encrypted``
    4.x. A tag-length-value table of ChaCha20 members -- ``vmlinuz.enc``,
    ``rootfs.uboot.img.enc``, a ``.dtb.enc`` and so on -- with the 12-byte
    nonce stored in the clear beside them. The 256-bit key is not in the
    image; the bootloader holds it. Members are located and reported here,
    but decryption needs that key.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

# Two container headers are in use across the family. The version string sits
# at a different offset in each.
HEADERS = {
    bytes.fromhex("06020106"): 0x28,    # .all  -- 3910/2962
    b"6216": 0x0D,                      # .sfw  -- 3912
}
VERSION_LEN = 0x18

# An ARM64 Image stores "ARM\x64" 0x38 bytes into its 64-byte header.
ARM64_MAGIC = b"ARM\x64"
ARM64_MAGIC_OFFSET = 0x38

FDT_MAGIC = bytes.fromhex("d00dfeed")
CPIO_MAGIC = b"070701"

PLAIN, ENCRYPTED = "plain", "encrypted"


@dataclass
class Kernel:
    offset: int
    text_offset: int
    image_size: int          # runtime footprint, includes BSS -- not a file size
    little_endian: bool

    @property
    def magic_offset(self) -> int:
        return self.offset + ARM64_MAGIC_OFFSET


@dataclass
class Dtb:
    offset: int
    size: int


@dataclass
class Member:
    """One entry of the encrypted tag-length-value table."""
    name: str
    offset: int
    size: int

    @property
    def encrypted(self) -> bool:
        return self.name.endswith(".enc")


@dataclass
class V3910Image:
    data: bytes
    kind: str
    version: str = ""
    kernel: Kernel | None = None
    dtbs: list[Dtb] = field(default_factory=list)
    members: list[Member] = field(default_factory=list)
    cpio_entries: int = 0
    nonce: bytes = b""

    @property
    def bootable(self) -> bool:
        """Can this be handed straight to QEMU?"""
        return self.kind == PLAIN and self.kernel is not None

    def kernel_bytes(self) -> bytes:
        """The kernel, from its header to the end of the image.

        `image_size` is the runtime footprint including BSS, so it cannot be
        used as a length. Trailing bytes are harmless -- the loader reads only
        what the kernel declares -- so carve generously rather than guess an
        end offset and risk truncating.
        """
        if self.kernel is None:
            raise ValueError("no ARM64 kernel in this image")
        return self.data[self.kernel.offset:]


def _header(data: bytes) -> int | None:
    """Return the version-string offset for a recognised header, else None."""
    for magic, version_offset in HEADERS.items():
        if data[:len(magic)] == magic:
            return version_offset
    return None


def looks_like_v3910(data: bytes) -> bool:
    """Cheap structural check that must not raise on arbitrary input."""
    if len(data) < 0x10000 or _header(data) is None:
        return False
    # An ARM64 kernel in the clear, or an encrypted member table.
    return bool(_find_kernel(data)) or b"vmlinuz" in data[:0x400]


def _find_kernel(data: bytes) -> Kernel | None:
    for m in re.finditer(re.escape(ARM64_MAGIC), data):
        head = m.start() - ARM64_MAGIC_OFFSET
        if head < 0 or head + 0x40 > len(data):
            continue
        text_offset, image_size, flags = struct.unpack_from("<QQQ", data, head + 8)
        if not (0 < image_size < (1 << 32)):
            continue
        return Kernel(head, text_offset, image_size, not (flags & 1))
    return None


def _find_dtbs(data: bytes) -> list[Dtb]:
    out = []
    for m in re.finditer(re.escape(FDT_MAGIC), data):
        o = m.start()
        if o + 28 > len(data):
            continue
        _, total, off_struct, off_strings, _, version, _ = struct.unpack_from(">7I", data, o)
        if version in (16, 17) and 0x30 < total < (1 << 21) and o + total <= len(data) \
                and off_struct < total and off_strings < total:
            out.append(Dtb(o, total))
    return out


def _parse_members(data: bytes) -> tuple[list[Member], bytes]:
    """Walk the tag-length-value table: [u32le namelen][name][u32le len][data].

    Records are zero-padded apart, so scan forward for the next plausible
    header rather than assuming they abut.
    """
    members: list[Member] = []
    nonce = b""
    pos = 0x40
    for _ in range(64):
        found = None
        for q in range(pos, min(pos + 0x8000, len(data) - 8)):
            nlen = struct.unpack_from("<I", data, q)[0]
            if not (0 < nlen <= 40):
                continue
            name = data[q + 4:q + 4 + nlen]
            if not all(33 <= b < 127 for b in name):
                continue
            dlen = struct.unpack_from("<I", data, q + 4 + nlen)[0]
            found = (name.decode(), dlen, q + 8 + nlen)
            break
        if not found:
            break
        name, dlen, doff = found
        if doff + dlen > len(data):
            break
        if name == "nonce":
            nonce = data[doff:doff + dlen]
        else:
            members.append(Member(name, doff, dlen))
        pos = doff + dlen if dlen else doff
    return members, nonce


def parse(data: bytes) -> V3910Image:
    version_offset = _header(data)
    if version_offset is None:
        raise ValueError("not a 3910-family image: header is %s, expected one of %s"
                         % (data[:4].hex(), ", ".join(m.hex() for m in HEADERS)))

    version = data[version_offset:version_offset + VERSION_LEN].split(b"\0")[0]
    kernel = _find_kernel(data)
    members, nonce = _parse_members(data)

    if kernel is not None:
        img = V3910Image(data, PLAIN, version.decode("latin-1", "replace"), kernel)
        img.dtbs = _find_dtbs(data)
        img.cpio_entries = data.count(CPIO_MAGIC)
        return img

    img = V3910Image(data, ENCRYPTED, version.decode("latin-1", "replace"))
    img.members, img.nonce = members, nonce
    return img


def qemu_argv(kernel_path: str, memory: int = 2048, cpu: str = "cortex-a57",
              cmdline: str = "console=ttyAMA0 earlycon") -> list[str]:
    """A QEMU command line that boots a carved kernel.

    ``-M virt`` builds its own device tree. The board's real device trees
    describe OCTEON TX hardware QEMU does not emulate, so passing one makes
    the boot fail earlier rather than later -- the kernel is multi-platform
    and is happier on virt's PL011 and PSCI.

    ``earlycon`` matters more than it looks: without it there is no output
    until the console driver probes, which on foreign hardware may be never.
    """
    return [
        "qemu-system-aarch64",
        "-M", "virt",
        "-cpu", cpu,
        "-m", str(memory),
        "-nographic",
        "-kernel", kernel_path,
        "-append", cmdline,
        "-no-reboot",
    ]
