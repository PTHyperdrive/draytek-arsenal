"""Read-only UBIFS reader for firmware images.

Rather than walking the on-flash index B-tree, this scans every node in the
volume and rebuilds the directory tree from the inode/dentry/data nodes it
finds. For a freshly built firmware image -- written once by ``mkfs.ubifs``,
never mounted read-write -- the scan sees exactly one live version of each node,
and it degrades gracefully on images the index would refuse to open.

Where several versions of a node do exist, the highest sequence number wins,
which matches how UBIFS itself resolves them.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import lzo1x

NODE_MAGIC = 0x06101831
CH_SZ = 24

INO_NODE, DATA_NODE, DENT_NODE, XENT_NODE = 0, 1, 2, 3
TRUN_NODE, PAD_NODE, SB_NODE, MST_NODE = 4, 5, 6, 7
REF_NODE, IDX_NODE, CS_NODE, ORPH_NODE = 8, 9, 10, 11

NODE_TYPE_NAMES = {
    0: "ino", 1: "data", 2: "dent", 3: "xent", 4: "trun", 5: "pad",
    6: "sb", 7: "mst", 8: "ref", 9: "idx", 10: "cs", 11: "orph",
    12: "auth", 13: "sig",
}

INO_NODE_SZ = 160
DENT_NODE_SZ = 56
DATA_NODE_SZ = 48

BLOCK_SIZE = 4096
ROOT_INO = 1

COMPR_NONE, COMPR_LZO, COMPR_ZLIB, COMPR_ZSTD = 0, 1, 2, 3
COMPR_NAMES = {0: "none", 1: "lzo", 2: "zlib", 3: "zstd"}

# UBIFS dentry types
ITYPE_REG, ITYPE_DIR, ITYPE_LNK = 0, 1, 2
ITYPE_BLK, ITYPE_CHR, ITYPE_FIFO, ITYPE_SOCK = 3, 4, 5, 6

S_IFMT = 0o170000
S_IFSOCK, S_IFLNK, S_IFREG = 0o140000, 0o120000, 0o100000
S_IFBLK, S_IFDIR, S_IFCHR, S_IFIFO = 0o060000, 0o040000, 0o020000, 0o010000


class UbifsError(Exception):
    pass


def _crc32(data: bytes) -> int:
    """CRC-32 as the kernel computes it: init 0xFFFFFFFF, no final inversion."""
    return (zlib.crc32(data) ^ 0xFFFFFFFF) & 0xFFFFFFFF


@dataclass
class Superblock:
    key_hash: int
    key_fmt: int
    flags: int
    min_io_size: int
    leb_size: int
    leb_cnt: int
    max_leb_cnt: int
    fanout: int
    fmt_version: int
    default_compr: int
    uuid: bytes

    @classmethod
    def parse(cls, node: bytes) -> "Superblock":
        o = CH_SZ
        key_hash, key_fmt = node[o + 2], node[o + 3]
        flags, min_io, leb_size, leb_cnt, max_leb_cnt = struct.unpack_from("<IIIII", node, o + 4)
        fanout, = struct.unpack_from("<I", node, o + 48)
        fmt_version, = struct.unpack_from("<I", node, o + 56)
        default_compr, = struct.unpack_from("<H", node, o + 60)
        uuid = node[o + 84:o + 100]
        return cls(key_hash, key_fmt, flags, min_io, leb_size, leb_cnt,
                   max_leb_cnt, fanout, fmt_version, default_compr, uuid)


@dataclass
class Inode:
    inum: int
    size: int
    mode: int
    uid: int
    gid: int
    nlink: int
    atime: int
    mtime: int
    ctime: int
    compr_type: int
    flags: int
    inline_data: bytes
    sqnum: int

    @property
    def ftype(self) -> int:
        return self.mode & S_IFMT

    @property
    def is_dir(self) -> bool:
        return self.ftype == S_IFDIR

    @property
    def is_reg(self) -> bool:
        return self.ftype == S_IFREG

    @property
    def is_link(self) -> bool:
        return self.ftype == S_IFLNK

    @property
    def link_target(self) -> str:
        return self.inline_data.decode("utf-8", "replace")

    @property
    def dev(self) -> Tuple[int, int]:
        """Decode a device node's major/minor from its inline data."""
        if len(self.inline_data) >= 4:
            raw, = struct.unpack_from("<I", self.inline_data, 0)
            if raw & 0xFFF00000 == 0 and len(self.inline_data) == 4:
                # new encoding: huge, 20-bit minor
                return (raw >> 8) & 0xFFF, (raw & 0xFF) | ((raw >> 12) & 0xFFF00)
            return (raw >> 8) & 0xFF, raw & 0xFF
        return 0, 0


@dataclass
class Dentry:
    parent: int
    inum: int
    dtype: int
    name: str
    sqnum: int


@dataclass
class ScanStats:
    nodes: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    bad_crc: int = 0
    lebs: int = 0


@dataclass
class Ubifs:
    sb: Optional[Superblock]
    inodes: Dict[int, Inode]
    dentries: Dict[int, List[Dentry]]
    data: Dict[int, Dict[int, bytes]]
    stats: ScanStats

    def children(self, inum: int) -> List[Dentry]:
        return sorted(self.dentries.get(inum, []), key=lambda d: d.name)

    def file_data(self, ino: Inode) -> bytes:
        """Reassemble a regular file's contents from its data nodes."""
        blocks = self.data.get(ino.inum, {})
        if not blocks:
            return b""
        out = bytearray()
        for idx in range(max(blocks) + 1):
            chunk = blocks.get(idx)
            if chunk is None:
                # Sparse hole.
                out.extend(b"\x00" * BLOCK_SIZE)
            else:
                out.extend(chunk)
        return bytes(out[:ino.size]) if ino.size else bytes(out)


def _decompress(buf: bytes, out_len: int, compr: int) -> bytes:
    if compr == COMPR_NONE:
        return buf[:out_len]
    if compr == COMPR_LZO:
        return lzo1x.decompress(buf, out_len)
    if compr == COMPR_ZLIB:
        # UBIFS uses raw deflate (no zlib header).
        return zlib.decompress(buf, -zlib.MAX_WBITS, out_len)
    if compr == COMPR_ZSTD:
        try:
            import zstandard  # optional
        except ImportError as exc:  # pragma: no cover
            raise UbifsError("zstd-compressed image needs the 'zstandard' package") from exc
        return zstandard.ZstdDecompressor().decompress(buf, max_output_size=out_len)
    raise UbifsError(f"unknown compression type {compr}")


def parse(volume: bytes, leb_size: int, verify_crc: bool = True) -> Ubifs:
    """Scan a UBIFS volume image and return its inodes, dentries and data."""
    sb: Optional[Superblock] = None
    inodes: Dict[int, Inode] = {}
    dentries: Dict[int, List[Dentry]] = {}
    data: Dict[int, Dict[int, bytes]] = {}
    # Track the winning sqnum so later duplicates do not clobber newer nodes.
    ino_sqnum: Dict[int, int] = {}
    dent_sqnum: Dict[Tuple[int, str], int] = {}
    data_sqnum: Dict[Tuple[int, int], int] = {}
    stats = ScanStats()

    for leb_start in range(0, len(volume), leb_size):
        leb = volume[leb_start:leb_start + leb_size]
        stats.lebs += 1
        off = 0
        while off + CH_SZ <= len(leb):
            magic, crc, sqnum, nlen, ntype, _gtype = struct.unpack_from("<IIQIBB", leb, off)
            if magic != NODE_MAGIC:
                break  # rest of the LEB is free space
            if nlen < CH_SZ or off + nlen > len(leb):
                break
            node = leb[off:off + nlen]

            if verify_crc and _crc32(node[8:nlen]) != crc:
                stats.bad_crc += 1
                off += (nlen + 7) & ~7
                continue

            stats.nodes += 1
            tname = NODE_TYPE_NAMES.get(ntype, str(ntype))
            stats.by_type[tname] = stats.by_type.get(tname, 0) + 1

            if ntype == SB_NODE and sb is None:
                sb = Superblock.parse(node)

            elif ntype == INO_NODE:
                inum, = struct.unpack_from("<I", node, CH_SZ)
                size, = struct.unpack_from("<Q", node, CH_SZ + 24)
                atime, ctime, mtime = struct.unpack_from("<QQQ", node, CH_SZ + 32)
                nlink, uid, gid, mode, flags, data_len = struct.unpack_from(
                    "<IIIIII", node, CH_SZ + 68)
                compr_type, = struct.unpack_from("<H", node, CH_SZ + 108)
                inline = node[INO_NODE_SZ:INO_NODE_SZ + data_len]
                if sqnum >= ino_sqnum.get(inum, -1):
                    ino_sqnum[inum] = sqnum
                    inodes[inum] = Inode(inum, size, mode, uid, gid, nlink,
                                         atime, mtime, ctime, compr_type, flags,
                                         inline, sqnum)

            elif ntype == DENT_NODE:
                parent, = struct.unpack_from("<I", node, CH_SZ)
                inum, = struct.unpack_from("<Q", node, CH_SZ + 16)
                dtype = node[CH_SZ + 25]
                nlen_name, = struct.unpack_from("<H", node, CH_SZ + 26)
                name = node[DENT_NODE_SZ:DENT_NODE_SZ + nlen_name].decode("utf-8", "replace")
                key = (parent, name)
                if sqnum >= dent_sqnum.get(key, -1):
                    dent_sqnum[key] = sqnum
                    bucket = dentries.setdefault(parent, [])
                    for i, existing in enumerate(bucket):
                        if existing.name == name:
                            bucket[i] = Dentry(parent, inum, dtype, name, sqnum)
                            break
                    else:
                        bucket.append(Dentry(parent, inum, dtype, name, sqnum))

            elif ntype == DATA_NODE:
                inum, = struct.unpack_from("<I", node, CH_SZ)
                key1, = struct.unpack_from("<I", node, CH_SZ + 4)
                block = key1 & 0x1FFFFFFF
                out_len, = struct.unpack_from("<I", node, CH_SZ + 16)
                compr, = struct.unpack_from("<H", node, CH_SZ + 20)
                payload = node[DATA_NODE_SZ:nlen]
                dkey = (inum, block)
                if sqnum >= data_sqnum.get(dkey, -1):
                    try:
                        chunk = _decompress(payload, out_len, compr)
                    except Exception as exc:
                        raise UbifsError(
                            f"inode {inum} block {block}: {COMPR_NAMES.get(compr, compr)} "
                            f"decompression failed: {exc}") from exc
                    data_sqnum[dkey] = sqnum
                    data.setdefault(inum, {})[block] = chunk

            off += (nlen + 7) & ~7

    return Ubifs(sb=sb, inodes=inodes, dentries=dentries, data=data, stats=stats)
