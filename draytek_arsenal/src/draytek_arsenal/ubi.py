"""Minimal, dependency-free UBI image reader.

Draytek's V3000 platform (Vigor 300B / 2960 / 3900) ships its firmware as a raw
UBI image rather than the RTOS or ``enc_Image`` containers handled elsewhere in
this toolkit, so we need to walk the UBI structures ourselves.

Only the subset needed to read a *firmware image file* is implemented: images are
pristine (every PEB is written once, erase counters are flat, no wear-levelling
history), so the volume reconstruction is a straight LEB-number sort rather than
the sequence-number arbitration a real attach would need.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional

EC_MAGIC = b"UBI#"
VID_MAGIC = b"UBI!"

EC_HDR_SIZE = 64
VID_HDR_SIZE = 64
VTBL_RECORD_SIZE = 172

LAYOUT_VOLUME_ID = 0x7FFFEFFF

VOL_TYPE_DYNAMIC = 1
VOL_TYPE_STATIC = 2
VOL_TYPE_NAMES = {VOL_TYPE_DYNAMIC: "dynamic", VOL_TYPE_STATIC: "static"}

# Erase-block sizes seen on Draytek NAND parts, most likely first.
CANDIDATE_PEB_SIZES = (0x20000, 0x40000, 0x10000, 0x8000)


def ubi_crc32(data: bytes) -> int:
    """CRC-32 as the kernel computes it: init 0xFFFFFFFF, no final inversion."""
    return (zlib.crc32(data) ^ 0xFFFFFFFF) & 0xFFFFFFFF


class UbiError(Exception):
    pass


@dataclass
class EcHeader:
    version: int
    ec: int
    vid_hdr_offset: int
    data_offset: int
    image_seq: int
    padding1: bytes
    padding2: bytes
    hdr_crc: int
    crc_ok: bool

    @classmethod
    def parse(cls, buf: bytes) -> "EcHeader":
        if len(buf) < EC_HDR_SIZE or buf[:4] != EC_MAGIC:
            raise UbiError("not a UBI EC header")
        version = buf[4]
        padding1 = buf[5:8]
        ec, vid_off, data_off, image_seq = struct.unpack(">QIII", buf[8:28])
        padding2 = buf[28:60]
        hdr_crc = struct.unpack(">I", buf[60:64])[0]
        return cls(
            version=version,
            ec=ec,
            vid_hdr_offset=vid_off,
            data_offset=data_off,
            image_seq=image_seq,
            padding1=padding1,
            padding2=padding2,
            hdr_crc=hdr_crc,
            crc_ok=ubi_crc32(buf[:60]) == hdr_crc,
        )

    @property
    def embedded_string(self) -> str:
        """Draytek stores the firmware version in the EC header's padding2."""
        return self.padding2.rstrip(b"\x00").lstrip(b"\x00").decode("ascii", "replace")


@dataclass
class VidHeader:
    version: int
    vol_type: int
    copy_flag: int
    compat: int
    vol_id: int
    lnum: int
    data_size: int
    used_ebs: int
    data_pad: int
    data_crc: int
    sqnum: int
    hdr_crc: int
    crc_ok: bool

    @classmethod
    def parse(cls, buf: bytes) -> Optional["VidHeader"]:
        if len(buf) < VID_HDR_SIZE or buf[:4] != VID_MAGIC:
            return None
        version, vol_type, copy_flag, compat = buf[4], buf[5], buf[6], buf[7]
        vol_id, lnum = struct.unpack(">II", buf[8:16])
        data_size, used_ebs, data_pad, data_crc = struct.unpack(">IIII", buf[20:36])
        sqnum = struct.unpack(">Q", buf[40:48])[0]
        hdr_crc = struct.unpack(">I", buf[60:64])[0]
        return cls(
            version=version,
            vol_type=vol_type,
            copy_flag=copy_flag,
            compat=compat,
            vol_id=vol_id,
            lnum=lnum,
            data_size=data_size,
            used_ebs=used_ebs,
            data_pad=data_pad,
            data_crc=data_crc,
            sqnum=sqnum,
            hdr_crc=hdr_crc,
            crc_ok=ubi_crc32(buf[:60]) == hdr_crc,
        )


@dataclass
class VtblRecord:
    vol_id: int
    reserved_pebs: int
    alignment: int
    data_pad: int
    vol_type: int
    upd_marker: int
    name: str
    flags: int
    crc_ok: bool

    @classmethod
    def parse(cls, vol_id: int, buf: bytes) -> Optional["VtblRecord"]:
        if len(buf) < VTBL_RECORD_SIZE:
            return None
        reserved_pebs, alignment, data_pad = struct.unpack(">III", buf[0:12])
        vol_type, upd_marker, name_len = buf[12], buf[13], struct.unpack(">H", buf[14:16])[0]
        name = buf[16:16 + min(name_len, 127)].decode("ascii", "replace")
        flags = buf[144]
        crc = struct.unpack(">I", buf[168:172])[0]
        if reserved_pebs == 0:
            return None  # empty slot
        return cls(
            vol_id=vol_id,
            reserved_pebs=reserved_pebs,
            alignment=alignment,
            data_pad=data_pad,
            vol_type=vol_type,
            upd_marker=upd_marker,
            name=name,
            flags=flags,
            crc_ok=ubi_crc32(buf[:168]) == crc,
        )


@dataclass
class Volume:
    vol_id: int
    name: str
    vol_type: int
    record: Optional[VtblRecord] = None
    # lnum -> (payload bytes, vid header)
    blocks: Dict[int, tuple] = field(default_factory=dict)

    @property
    def type_name(self) -> str:
        return VOL_TYPE_NAMES.get(self.vol_type, f"unknown({self.vol_type})")

    def data(self) -> bytes:
        """Concatenate logical erase blocks in LEB order."""
        if not self.blocks:
            return b""
        out = bytearray()
        for lnum in range(max(self.blocks) + 1):
            entry = self.blocks.get(lnum)
            if entry is None:
                # A hole: unmapped LEB reads as 0xFF on NAND.
                out.extend(b"\xff" * self._leb_size())
                continue
            payload, vid = entry
            if vid.vol_type == VOL_TYPE_STATIC and vid.data_size:
                out.extend(payload[:vid.data_size])
            else:
                out.extend(payload)
        return bytes(out)

    def _leb_size(self) -> int:
        for payload, _ in self.blocks.values():
            return len(payload)
        return 0

    def verify(self) -> List[str]:
        """Return a list of human-readable integrity problems."""
        problems = []
        for lnum, (payload, vid) in sorted(self.blocks.items()):
            if not vid.crc_ok:
                problems.append(f"vol {self.vol_id} LEB {lnum}: bad VID header CRC")
            if vid.vol_type == VOL_TYPE_STATIC and vid.data_size:
                if ubi_crc32(payload[:vid.data_size]) != vid.data_crc:
                    problems.append(f"vol {self.vol_id} LEB {lnum}: bad data CRC")
        missing = [n for n in range(max(self.blocks) + 1) if n not in self.blocks]
        if missing:
            problems.append(f"vol {self.vol_id}: unmapped LEBs {missing[:8]}"
                            + ("..." if len(missing) > 8 else ""))
        return problems


@dataclass
class UbiImage:
    peb_size: int
    leb_size: int
    vid_hdr_offset: int
    data_offset: int
    image_seq: int
    total_pebs: int
    empty_pebs: int
    volumes: Dict[int, Volume]
    ec_header: EcHeader

    @property
    def data_volumes(self) -> List[Volume]:
        return [v for vid, v in sorted(self.volumes.items()) if vid != LAYOUT_VOLUME_ID]


def detect_peb_size(data: bytes) -> int:
    """Find the erase-block size by locating the second EC header."""
    if not data.startswith(EC_MAGIC):
        raise UbiError("image does not start with a UBI EC header")
    for size in CANDIDATE_PEB_SIZES:
        if len(data) % size:
            continue
        # A real PEB size makes every block boundary an EC header or blank flash.
        good = blank = 0
        for off in range(0, min(len(data), size * 24), size):
            chunk = data[off:off + 4]
            if chunk == EC_MAGIC:
                good += 1
            elif chunk == b"\xff\xff\xff\xff":
                blank += 1
            else:
                good = -1
                break
        if good > 1 and good + blank == len(data[:size * 24]) // size:
            return size
    raise UbiError("could not determine PEB size")


def parse(data: bytes, peb_size: Optional[int] = None) -> UbiImage:
    """Parse a raw UBI image into volumes."""
    peb_size = peb_size or detect_peb_size(data)
    first = EcHeader.parse(data[:EC_HDR_SIZE])
    leb_size = peb_size - first.data_offset

    volumes: Dict[int, Volume] = {}
    layout_records: Dict[int, VtblRecord] = {}
    total = empty = 0

    for off in range(0, len(data), peb_size):
        peb = data[off:off + peb_size]
        total += 1
        if peb[:4] != EC_MAGIC:
            empty += 1
            continue
        ec = EcHeader.parse(peb[:EC_HDR_SIZE])
        vid = VidHeader.parse(peb[ec.vid_hdr_offset:ec.vid_hdr_offset + VID_HDR_SIZE])
        if vid is None:
            empty += 1  # erased/unmapped PEB (EC header only)
            continue

        payload = peb[ec.data_offset:]
        vol = volumes.get(vid.vol_id)
        if vol is None:
            vol = Volume(vol_id=vid.vol_id, name="", vol_type=vid.vol_type)
            volumes[vid.vol_id] = vol
        vol.blocks[vid.lnum] = (payload, vid)

        if vid.vol_id == LAYOUT_VOLUME_ID:
            for i in range(0, len(payload) // VTBL_RECORD_SIZE):
                rec = VtblRecord.parse(i, payload[i * VTBL_RECORD_SIZE:(i + 1) * VTBL_RECORD_SIZE])
                if rec is not None:
                    layout_records.setdefault(i, rec)

    for vol_id, rec in layout_records.items():
        vol = volumes.get(vol_id)
        if vol is not None:
            vol.name = rec.name
            vol.record = rec
    if LAYOUT_VOLUME_ID in volumes:
        volumes[LAYOUT_VOLUME_ID].name = "layout"

    return UbiImage(
        peb_size=peb_size,
        leb_size=leb_size,
        vid_hdr_offset=first.vid_hdr_offset,
        data_offset=first.data_offset,
        image_seq=first.image_seq,
        total_pebs=total,
        empty_pebs=empty,
        volumes=volumes,
        ec_header=first,
    )
