"""Parse and extract Draytek V3000-family firmware (Vigor 300B / 2960 / 3900)."""

from __future__ import annotations

import json
import os
import stat
import sys
from typing import Any, Dict, List, Optional

from draytek_arsenal import ubi, ubifs, v3000
from draytek_arsenal.commands.base import Command


class ExtractV3000Command(Command):

    @staticmethod
    def name() -> str:
        return "extract_v3000"

    @staticmethod
    def description() -> str:
        return ("Parse, verify and extract Draytek V3000-family firmware "
                "(Vigor 300B / 2960 / 3900 .all/.rst/.cv3/.ota)")

    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["firmware"], "kwargs": {"type": str, "help": "Path to the firmware image"}},
            {"flags": ["--fs", "-f"], "kwargs": {
                "type": str, "required": False,
                "help": "Directory to extract the root filesystem into"}},
            {"flags": ["--ubi"], "kwargs": {
                "type": str, "required": False,
                "help": "Write the raw ubinized UBI image to this path"}},
            {"flags": ["--volume"], "kwargs": {
                "type": str, "required": False,
                "help": "Write the raw UBIFS volume image to this path"}},
            {"flags": ["--signature"], "kwargs": {
                "type": str, "required": False,
                "help": "Write the OTA RSA signature blob to this path (.ota input only)"}},
            {"flags": ["--list", "-l"], "kwargs": {
                "action": "store_true", "help": "List filesystem contents"}},
            {"flags": ["--json"], "kwargs": {
                "action": "store_true", "help": "Emit image metadata as JSON"}},
            {"flags": ["--no-verify"], "kwargs": {
                "action": "store_true", "help": "Skip UBIFS node CRC verification"}},
        ]

    @staticmethod
    def execute(args) -> None:
        with open(args.firmware, "rb") as fh:
            data = fh.read()

        try:
            img = v3000.parse(data)
        except v3000.V3000Error as exc:
            print(f"[x] {exc}", file=sys.stderr)
            raise SystemExit(1)

        _report_container(img, as_json=args.json)

        if args.signature:
            if img.ota_signature is None:
                print("[!] input has no OTA signature; --signature ignored")
            else:
                _write(args.signature, img.ota_signature)
                print(f"[+] OTA signature ({len(img.ota_signature)} bytes) -> {args.signature}")

        if args.ubi:
            _write(args.ubi, img.ubi)
            print(f"[+] UBI image ({len(img.ubi):,} bytes) -> {args.ubi}")

        if not (args.fs or args.volume or args.list):
            return

        ubi_img = ubi.parse(img.ubi)
        print(f"\n[*] UBI: PEB=0x{ubi_img.peb_size:x} LEB=0x{ubi_img.leb_size:x} "
              f"PEBs={ubi_img.total_pebs} image_seq=0x{ubi_img.image_seq:08x}")
        if ubi_img.ec_header.embedded_string:
            print(f"[*] version string in EC header padding: "
                  f"{ubi_img.ec_header.embedded_string!r}")
        for vol in ubi_img.data_volumes:
            print(f"[*] volume id={vol.vol_id} name={vol.name!r} type={vol.type_name} "
                  f"LEBs={len(vol.blocks)}")
            for problem in vol.verify():
                print(f"    ! {problem}")

        volumes = ubi_img.data_volumes
        if not volumes:
            print("[x] no data volumes found", file=sys.stderr)
            raise SystemExit(1)
        rootfs = next((v for v in volumes if v.name == "rootfs"), volumes[0])
        raw = rootfs.data()

        if args.volume:
            _write(args.volume, raw)
            print(f"[+] volume {rootfs.name!r} ({len(raw):,} bytes) -> {args.volume}")

        if not (args.fs or args.list):
            return

        print(f"\n[*] parsing UBIFS in volume {rootfs.name!r}...")
        fs = ubifs.parse(raw, ubi_img.leb_size, verify_crc=not args.no_verify)
        if fs.sb:
            print(f"[*] UBIFS fmt v{fs.sb.fmt_version}, default compression "
                  f"{ubifs.COMPR_NAMES.get(fs.sb.default_compr, fs.sb.default_compr)}, "
                  f"uuid {fs.sb.uuid.hex()}")
        print(f"[*] {fs.stats.nodes:,} nodes ({fs.stats.bad_crc} bad CRC), "
              f"{len(fs.inodes):,} inodes")

        entries = _walk(fs)
        print(f"[*] {len(entries):,} directory entries reachable from root")

        if args.list:
            for path, ino in entries:
                _print_entry(path, ino)

        if args.fs:
            _extract(fs, entries, args.fs)


def _report_container(img: v3000.V3000Image, as_json: bool = False) -> None:
    info = {
        "container": "ota" if img.is_ota else "all",
        "machine_type": img.machine_type,
        "model": img.model,
        "kind": img.kind,
        "encrypted": False,
        "stored_md5": img.stored_md5,
        "actual_md5": img.actual_md5,
        "md5_ok": img.md5_ok,
        "stored_crc32": img.stored_crc32,
        "actual_crc32": img.actual_crc32,
        "crc32_ok": img.crc_ok,
        "payload_bytes": len(img.payload),
        "ubi_bytes": len(img.ubi),
    }
    if img.is_ota:
        info["ota_signature_bytes"] = len(img.ota_signature or b"")

    if as_json:
        print(json.dumps(info, indent=2))
        return

    print(f"[+] Draytek V3000 container")
    print(f"    machine type : {img.machine_type}  ({img.model}, {img.kind})")
    if img.is_ota:
        print(f"    OTA wrapper  : yes -- {len(img.ota_signature or b'')}-byte "
              f"RSA-2048 signature prefix")
    print(f"    payload      : {len(img.payload):,} bytes (machine-type line + UBI image)")
    print(f"    UBI image    : {len(img.ubi):,} bytes")
    print(f"    MD5          : {img.stored_md5} "
          f"{'OK' if img.md5_ok else 'MISMATCH (computed ' + img.actual_md5 + ')'}")
    print(f"    CRC32        : {img.stored_crc32} "
          f"{'OK' if img.crc_ok else 'MISMATCH (computed ' + img.actual_crc32 + ')'}")
    print(f"    encryption   : none (payload is a plain ubinized UBI image)")


def _walk(fs: ubifs.Ubifs):
    """Depth-first walk from the root inode, guarding against dentry loops."""
    out = []
    seen = set()

    def rec(inum: int, path: str) -> None:
        if inum in seen:
            return
        seen.add(inum)
        for dent in fs.children(inum):
            child = fs.inodes.get(dent.inum)
            sub = f"{path}/{dent.name}"
            out.append((sub, child))
            if child is not None and child.is_dir:
                rec(dent.inum, sub)

    rec(ubifs.ROOT_INO, "")
    return out


def _print_entry(path: str, ino: Optional[ubifs.Inode]) -> None:
    if ino is None:
        print(f"    ????????? {'?':>4} {'?':>4} {0:>10}  {path}  [missing inode]")
        return
    mode = stat.filemode(ino.mode)
    suffix = f" -> {ino.link_target}" if ino.is_link else ""
    print(f"    {mode} {ino.uid:>4} {ino.gid:>4} {ino.size:>10,}  {path}{suffix}")


def _safe_join(root: str, path: str) -> str:
    """Join a firmware-supplied path under ``root``, refusing to escape it."""
    root_abs = os.path.abspath(root)
    target = os.path.abspath(os.path.join(root_abs, path.lstrip("/")))
    if target != root_abs and not target.startswith(root_abs + os.sep):
        raise ValueError(f"refusing path traversal: {path!r}")
    return target


def _write(path: str, data: bytes) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def _extract(fs: ubifs.Ubifs, entries, dest: str) -> None:
    os.makedirs(dest, exist_ok=True)
    counts = {"dir": 0, "file": 0, "symlink": 0, "special": 0, "skipped": 0}
    deferred_links = []
    manifest = []

    for path, ino in entries:
        if ino is None:
            counts["skipped"] += 1
            continue
        try:
            target = _safe_join(dest, path)
        except ValueError as exc:
            print(f"[!] {exc}")
            counts["skipped"] += 1
            continue

        if ino.is_dir:
            os.makedirs(target, exist_ok=True)
            counts["dir"] += 1
        elif ino.is_reg:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(fs.file_data(ino))
            counts["file"] += 1
        elif ino.is_link:
            deferred_links.append((target, ino.link_target))
            counts["symlink"] += 1
        else:
            counts["special"] += 1
        manifest.append(_manifest_entry(path, ino))

    # Symlinks last, so their targets already exist where possible.
    link_failures = 0
    for target, dest_path in deferred_links:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.lexists(target):
            continue
        try:
            os.symlink(dest_path, target)
        except (OSError, NotImplementedError):
            # Windows without developer mode, or a filesystem with no symlink
            # support: leave a readable placeholder instead of failing.
            link_failures += 1
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(dest_path)

    manifest_path = os.path.join(dest, ".draytek-manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)

    print(f"[+] extracted to {dest}")
    print(f"    dirs={counts['dir']} files={counts['file']} symlinks={counts['symlink']} "
          f"special={counts['special']} skipped={counts['skipped']}")
    if link_failures:
        print(f"    note: {link_failures} symlinks written as plain text files "
              f"(no symlink privilege on this platform)")
    print(f"    ownership, permissions and device nodes recorded in {manifest_path}")


def _manifest_entry(path: str, ino: ubifs.Inode) -> Dict[str, Any]:
    entry = {
        "path": path,
        "mode": oct(ino.mode),
        "uid": ino.uid,
        "gid": ino.gid,
        "size": ino.size,
        "mtime": ino.mtime,
    }
    if ino.is_link:
        entry["symlink"] = ino.link_target
    elif not (ino.is_dir or ino.is_reg):
        major, minor = ino.dev
        entry["device"] = {"major": major, "minor": minor}
    return entry
