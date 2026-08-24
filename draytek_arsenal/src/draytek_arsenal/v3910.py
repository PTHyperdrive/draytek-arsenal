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

# The root filesystem is a cpio archive in an LZ4 *legacy* frame: the magic,
# then [u32le block_length][block] repeated, each block decompressing to at
# most 8 MiB. Note this is not the modern LZ4 frame format.
LZ4_LEGACY_MAGIC = bytes.fromhex("02214c18")
LZ4_LEGACY_BLOCK_MAX = 8 << 20

CPIO_HEADER_LEN = 110           # "070701" + 13 fields of 8 hex digits
CPIO_TRAILER = "TRAILER!!!"
S_IFMT, S_IFDIR, S_IFLNK, S_IFREG = 0o170000, 0o040000, 0o120000, 0o100000

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
    initramfs_offset: int | None = None
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
        img.initramfs_offset = find_initramfs(data)
        return img

    img = V3910Image(data, ENCRYPTED, version.decode("latin-1", "replace"))
    img.members, img.nonce = members, nonce
    return img


@dataclass
class CpioEntry:
    name: str
    mode: int
    data: bytes

    @property
    def is_dir(self) -> bool:
        return self.mode & S_IFMT == S_IFDIR

    @property
    def is_symlink(self) -> bool:
        return self.mode & S_IFMT == S_IFLNK

    @property
    def is_file(self) -> bool:
        return self.mode & S_IFMT == S_IFREG


def find_initramfs(data: bytes) -> int | None:
    """Offset of the LZ4 legacy frame holding the root filesystem.

    A bare search for the cpio magic finds the kernel's own error strings
    ("no cpio magic") and literals inside compressed data, so look for the
    LZ4 frame instead and confirm by what it decompresses to.
    """
    for m in re.finditer(re.escape(LZ4_LEGACY_MAGIC), data):
        try:
            head = _lz4_legacy(data, m.start(), stop_after=1)
        except Exception:
            continue
        if head[:6] == CPIO_MAGIC:
            return m.start()
    return None


def _lz4_legacy(data: bytes, offset: int, stop_after: int | None = None) -> bytes:
    """Decompress an LZ4 legacy frame at `offset`."""
    from draytek_arsenal.lz4_block import decompress as lz4_block

    pos, chunks, blocks = offset + 4, [], 0
    while pos + 4 <= len(data):
        size = struct.unpack_from("<I", data, pos)[0]
        if size == 0 or size > LZ4_LEGACY_BLOCK_MAX or pos + 4 + size > len(data):
            break
        chunks.append(lz4_block(data[pos + 4:pos + 4 + size]))
        pos += 4 + size
        blocks += 1
        if stop_after and blocks >= stop_after:
            break
    return b"".join(chunks)


def initramfs_bytes(data: bytes, offset: int | None = None) -> bytes:
    """The decompressed cpio archive."""
    if offset is None:
        offset = find_initramfs(data)
    if offset is None:
        raise ValueError("no LZ4-compressed cpio archive found")
    return _lz4_legacy(data, offset)


def cpio_entries(buf: bytes):
    """Walk a cpio 'newc' archive, yielding CpioEntry."""
    off = 0
    while off + CPIO_HEADER_LEN <= len(buf):
        if buf[off:off + 6] != CPIO_MAGIC:
            break
        try:
            fields = [int(buf[off + 6 + i * 8: off + 14 + i * 8], 16) for i in range(13)]
        except ValueError:
            break
        mode, size, namesize = fields[1], fields[6], fields[11]
        name = buf[off + CPIO_HEADER_LEN: off + CPIO_HEADER_LEN + namesize - 1]
        body = (off + CPIO_HEADER_LEN + namesize + 3) & ~3
        off = (body + size + 3) & ~3
        decoded = name.decode("latin-1")
        if decoded == CPIO_TRAILER:
            break
        yield CpioEntry(decoded, mode, buf[body:body + size])


def extract_cpio(buf: bytes, out_dir: str) -> dict:
    """Unpack a cpio archive to disk.

    Symlinks are recreated where the platform allows it; where it does not
    (Windows without developer mode) they are recorded in `symlinks.txt` so
    the tree stays clean for grepping rather than filling with stub files.
    """
    import os

    root = os.path.abspath(out_dir)
    os.makedirs(root, exist_ok=True)
    stats = {"files": 0, "dirs": 0, "symlinks": 0, "unlinked": 0, "bytes": 0,
             "skipped": 0}
    unlinked = []

    for entry in cpio_entries(buf):
        dst = os.path.abspath(os.path.join(root, entry.name))
        if os.path.commonpath((root, dst)) != root:
            stats["skipped"] += 1          # path traversal
            continue

        if entry.is_dir:
            os.makedirs(dst, exist_ok=True)
            stats["dirs"] += 1
        elif entry.is_symlink:
            target = entry.data.split(b"\0")[0].decode("latin-1")
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                if not os.path.lexists(dst):
                    os.symlink(target, dst)
                stats["symlinks"] += 1
            except OSError:
                unlinked.append("%s -> %s" % (entry.name, target))
                stats["unlinked"] += 1
        elif entry.is_file:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as fh:
                fh.write(entry.data)
            stats["files"] += 1
            stats["bytes"] += len(entry.data)

    if unlinked:
        with open(os.path.join(root, "symlinks.txt"), "w") as fh:
            fh.write("\n".join(unlinked) + "\n")
    return stats


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
