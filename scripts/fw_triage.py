#!/usr/bin/env python3
"""Triage an unknown firmware image before trying to parse it.

The question worth answering first is almost always "is this actually
encrypted?", because getting it wrong sends you hunting for a key that may not
exist. Vendor documentation and prior write-ups are frequently wrong or apply
to a different model in the same product line; the file itself is not.

Three cheap signals answer it:

* **Entropy.** Encrypted data pins flat near 8.0 bits/byte across the whole
  image. Compressed data typically lands around 7.0-7.9 and varies between
  windows. A varying profile in that band means compression, not a cipher.
* **Magic bytes.** Plaintext ELF headers, filesystem superblocks or gzip
  members cannot survive encryption. Finding hundreds of them settles it.
* **Header strings.** Vendors put version tags, model names and checksums in
  plain ASCII far more often than you would expect.

Stdlib only, and nothing here is Draytek-specific -- it works on any firmware
blob.

    python3 fw_triage.py firmware.bin [more.bin ...]
"""

from __future__ import annotations

import argparse
import collections
import math
import os
import re
import sys
from typing import Dict, List, Tuple

# Magic values worth knowing about in an embedded image. Order is not
# significant; counts and offsets are what matter.
MAGICS: Dict[str, bytes] = {
    "UBI (erase blk)":  b"UBI#",
    "UBI (vid hdr)":    b"UBI!",
    "UBIFS node":       b"\x31\x18\x10\x06",
    "squashfs LE":      b"hsqs",
    "squashfs BE":      b"sqsh",
    "cramfs":           b"\x45\x3d\xcd\x28",
    "JFFS2":            b"\x85\x19",
    "romfs":            b"-rom1fs-",
    "ext superblock":   b"\x53\xef",
    "cpio (newc)":      b"070701",
    "gzip":             b"\x1f\x8b\x08",
    "bzip2":            b"BZh",
    "xz":               b"\xfd7zXZ",
    "lzma":             b"\x5d\x00\x00",
    "lz4 (legacy)":     b"\x02\x21\x4c\x18",
    "lz4 (frame)":      b"\x04\x22\x4d\x18",
    "zstd":             b"\x28\xb5\x2f\xfd",
    "zip":              b"PK\x03\x04",
    "uImage":           b"\x27\x05\x19\x56",
    "ELF":              b"\x7fELF",
    "device tree":      b"\xd0\x0d\xfe\xed",
    "ARM64 kernel":     b"ARM\x64",
    "PEM key/cert":     b"-----BEGIN",
}

WINDOW = 1 << 20  # 1 MiB entropy window


def entropy(buf: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not buf:
        return 0.0
    counts = collections.Counter(buf)
    n = len(buf)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def hexdump(buf: bytes, base: int = 0, width: int = 16) -> List[str]:
    out = []
    for off in range(0, len(buf), width):
        chunk = buf[off:off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"  {base + off:08x}  {hexs:<{width * 3 - 1}}  |{text}|")
    return out


def find_all(data: bytes, needle: bytes, limit: int) -> Tuple[int, List[int]]:
    """Return (total count, first `limit` offsets)."""
    offsets = []
    start = 0
    total = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        total += 1
        if len(offsets) < limit:
            offsets.append(i)
        start = i + 1
    return total, offsets


def entropy_profile(data: bytes) -> List[float]:
    return [entropy(data[i:i + WINDOW]) for i in range(0, len(data), WINDOW)]


def sparkline(values: List[float], lo: float = 0.0, hi: float = 8.0) -> str:
    blocks = "▁▂▃▄▅▆▇█"
    if not values:
        return ""
    out = []
    for v in values:
        frac = 0.0 if hi == lo else (v - lo) / (hi - lo)
        idx = max(0, min(len(blocks) - 1, int(frac * len(blocks))))
        out.append(blocks[idx])
    return "".join(out)


def verdict(data: bytes, profile: List[float], magic_hits: int) -> List[str]:
    """A deliberately conservative read of the evidence."""
    lines = []
    if not profile:
        return ["  file too small to judge"]

    overall = entropy(data[:8 << 20])
    hi = max(profile)
    lo = min(profile)
    spread = hi - lo

    if magic_hits > 0:
        lines.append(
            f"  NOT ENCRYPTED -- {magic_hits} plaintext magic value(s) found. "
            "Structured data cannot survive a cipher.")
    elif overall > 7.98 and spread < 0.05:
        lines.append(
            "  LIKELY ENCRYPTED (or solid-compressed) -- entropy is flat and "
            "saturated, with no recognisable structure.")
    elif overall > 7.5:
        lines.append(
            "  LIKELY COMPRESSED -- high but uneven entropy is what packed "
            "data looks like; a cipher would not vary between windows.")
    else:
        lines.append(
            "  LIKELY PLAINTEXT / MIXED -- entropy is well below the "
            "compressed range over at least part of the image.")

    lines.append(f"  entropy: overall {overall:.3f}, window min {lo:.3f}, "
                 f"max {hi:.3f}, spread {spread:.3f}")
    if spread < 0.05 and magic_hits == 0:
        lines.append("  note: a uniform profile is the signature to watch for; "
                     "compression almost always varies.")
    return lines


def triage(path: str, head_bytes: int, str_bytes: int, min_str: int) -> None:
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        data = fh.read()

    print("=" * 78)
    print(f"{os.path.basename(path)}   {size:,} bytes (0x{size:x})")
    print("=" * 78)

    print("\n-- header --")
    for line in hexdump(data[:head_bytes]):
        print(line)

    print("\n-- printable strings in first "
          f"{str_bytes} bytes (>= {min_str} chars) --")
    found = re.findall(rb"[\x20-\x7e]{%d,}" % min_str, data[:str_bytes])
    if found:
        for s in found[:40]:
            print(f"  {s.decode('ascii', 'replace')}")
    else:
        print("  (none)")

    print("\n-- magic scan --")
    magic_hits = 0
    for name, needle in MAGICS.items():
        total, offsets = find_all(data, needle, 5)
        if not total:
            continue
        # Two-byte magics collide by chance constantly; report but discount.
        reliable = len(needle) >= 4
        if reliable:
            magic_hits += total
        locs = ", ".join(f"0x{o:x}" for o in offsets)
        more = " ..." if total > len(offsets) else ""
        flag = "" if reliable else "  (short magic -- may be coincidence)"
        print(f"  {name:<18} n={total:<6} at {locs}{more}{flag}")
    if magic_hits == 0:
        print("  (no reliable magic values found)")

    print("\n-- entropy profile (1 MiB windows, 0-8 bits/byte) --")
    profile = entropy_profile(data)
    print(f"  {sparkline(profile)}")
    if len(profile) <= 48:
        print("  " + " ".join(f"{v:.2f}" for v in profile))

    print("\n-- verdict --")
    for line in verdict(data, profile, magic_hits):
        print(line)
    print()


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Triage an unknown firmware image: entropy, magic values "
                    "and header strings, to decide whether it is encrypted "
                    "before trying to parse it.")
    ap.add_argument("firmware", nargs="+", help="image file(s) to inspect")
    ap.add_argument("--head", type=int, default=128,
                    help="bytes to hexdump from the start (default 128)")
    ap.add_argument("--strings-window", type=int, default=4096,
                    help="bytes to scan for strings (default 4096)")
    ap.add_argument("--min-string", type=int, default=5,
                    help="minimum string length (default 5)")
    args = ap.parse_args(argv)

    rc = 0
    for path in args.firmware:
        if not os.path.isfile(path):
            print(f"[x] not a file: {path}", file=sys.stderr)
            rc = 1
            continue
        triage(path, args.head, args.strings_window, args.min_string)
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
