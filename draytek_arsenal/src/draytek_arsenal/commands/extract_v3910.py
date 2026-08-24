"""extract_v3910 -- unpack and emulate Vigor 3910 / 2962 / 3912 firmware."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List

from draytek_arsenal import v3910
from draytek_arsenal.commands.base import Command

KERNEL_NAME = "Image"


class ExtractV3910Command(Command):
    @staticmethod
    def name() -> str:
        return "extract_v3910"

    @staticmethod
    def description() -> str:
        return ("Command used to extract and emulate Draytek ARM64 Linux packages "
                "(Vigor 3910 / 2962 / 3912)")

    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["firmware"], "kwargs": {"type": str, "help": "Path to the firmware"}},
            {"flags": ["--kernel", "-k"], "kwargs": {
                "type": str, "required": False,
                "help": "File to write the ARM64 kernel Image to"}},
            {"flags": ["--rootfs", "-r"], "kwargs": {
                "type": str, "required": False,
                "help": "Directory to unpack the root filesystem into"}},
            {"flags": ["--dtb-dir", "-d"], "kwargs": {
                "type": str, "required": False,
                "help": "Directory to write the board device trees to"}},
            {"flags": ["--list", "-l"], "kwargs": {
                "action": "store_true", "help": "List the image contents and exit"}},
            {"flags": ["--json"], "kwargs": {
                "action": "store_true", "help": "Emit the listing as JSON"}},
            {"flags": ["--qemu"], "kwargs": {
                "action": "store_true",
                "help": "Print a ready-to-run qemu-system-aarch64 command line"}},
            {"flags": ["--run"], "kwargs": {
                "action": "store_true",
                "help": "Extract the kernel to a temp file and boot it under QEMU"}},
            {"flags": ["--memory", "-m"], "kwargs": {
                "type": int, "default": 2048, "help": "Guest RAM in MB (default 2048)"}},
            {"flags": ["--cpu"], "kwargs": {
                "type": str, "default": "cortex-a57", "help": "QEMU CPU model"}},
            {"flags": ["--cmdline"], "kwargs": {
                "type": str, "default": "console=ttyAMA0 earlycon",
                "help": "Kernel command line"}},
        ]

    @staticmethod
    def execute(args) -> None:
        with open(args.firmware, "rb") as fh:
            data = fh.read()

        try:
            img = v3910.parse(data)
        except ValueError as exc:
            print("[x] %s" % exc)
            return

        if args.json:
            print(json.dumps(_describe(img, args.firmware), indent=2))
            return

        _report(img, args.firmware)

        if args.list:
            return

        if img.kind == v3910.ENCRYPTED:
            print("\n[x] This image is encrypted; there is nothing to boot.")
            print("    The 256-bit ChaCha20 key is held by the bootloader, not the image.")
            print("    A 3.9.x build of the same model is shipped in the clear and boots.")
            return

        kernel_path = args.kernel
        if args.run and not kernel_path:
            kernel_path = os.path.join(os.path.dirname(os.path.abspath(args.firmware)),
                                       KERNEL_NAME)

        if kernel_path:
            with open(kernel_path, "wb") as fh:
                fh.write(img.kernel_bytes())
            print("\n[+] Kernel extracted to %s (%d bytes)"
                  % (kernel_path, len(img.kernel_bytes())))

        if args.rootfs:
            offset = v3910.find_initramfs(data)
            if offset is None:
                print()
                print("[x] No LZ4-compressed cpio archive found")
            else:
                print()
                print("[*] Initramfs: LZ4 legacy frame @ 0x%08X" % offset)
                archive = v3910.initramfs_bytes(data, offset)
                print("[*] Decompressed to %d bytes of cpio" % len(archive))
                st = v3910.extract_cpio(archive, args.rootfs)
                print("[+] Root filesystem unpacked to %s" % args.rootfs)
                print("    %d files (%d bytes), %d dirs, %d symlinks"
                      % (st["files"], st["bytes"], st["dirs"], st["symlinks"]))
                if st["unlinked"]:
                    print("    %d symlinks could not be created; listed in symlinks.txt"
                          % st["unlinked"])
                if st["skipped"]:
                    print("    %d entries skipped (path traversal)" % st["skipped"])

        if args.dtb_dir:
            os.makedirs(args.dtb_dir, exist_ok=True)
            for i, dtb in enumerate(img.dtbs):
                dst = os.path.join(args.dtb_dir, "board_%02d_%08x.dtb" % (i, dtb.offset))
                with open(dst, "wb") as fh:
                    fh.write(data[dtb.offset:dtb.offset + dtb.size])
            print("[+] %d device trees written to %s" % (len(img.dtbs), args.dtb_dir))
            print("    Note: these describe OCTEON TX hardware. Do not pass one to")
            print("    '-M virt' -- virt builds its own, and the board's tree makes")
            print("    the boot fail earlier, not work better.")

        if args.qemu or args.run:
            argv = v3910.qemu_argv(kernel_path or KERNEL_NAME, args.memory,
                                   args.cpu, args.cmdline)
            print("\n[*] " + " ".join(_quote(a) for a in argv))

        if args.run:
            if not kernel_path:
                print("[x] --run needs a kernel; pass --kernel")
                return
            exe = shutil.which(argv[0])
            if exe is None:
                print("[x] %s not found on PATH" % argv[0])
                return
            print("[*] booting (ctrl-a x to quit QEMU)\n")
            subprocess.run([exe] + argv[1:])


def _quote(arg: str) -> str:
    return '"%s"' % arg if " " in arg else arg


def _describe(img, path) -> dict:
    out = {"firmware": path, "kind": img.kind, "version": img.version,
           "bootable": img.bootable}
    if img.kernel:
        out["kernel"] = {"offset": img.kernel.offset,
                         "text_offset": img.kernel.text_offset,
                         "image_size": img.kernel.image_size,
                         "endian": "little" if img.kernel.little_endian else "big"}
        out["device_trees"] = len(img.dtbs)
        out["initramfs_offset"] = img.initramfs_offset
    if img.members:
        out["nonce"] = img.nonce.decode("latin-1", "replace")
        out["members"] = [{"name": m.name, "offset": m.offset, "size": m.size,
                           "encrypted": m.encrypted} for m in img.members]
    return out


def _report(img, path) -> None:
    print("[+] %s" % os.path.basename(path))
    print("    version : %s" % (img.version or "(unknown)"))
    print("    type    : %s" % ("plain ARM64 Linux" if img.kind == v3910.PLAIN
                                else "encrypted (ChaCha20)"))

    if img.kernel:
        k = img.kernel
        print("    kernel  : ARM64 Image @ 0x%08X, text_offset 0x%X, %s-endian"
              % (k.offset, k.text_offset, "little" if k.little_endian else "big"))
        print("              image_size %d bytes (runtime footprint, includes BSS)"
              % k.image_size)
        print("    dtbs    : %d board device trees" % len(img.dtbs))
        if img.initramfs_offset is not None:
            print("    rootfs  : LZ4 cpio initramfs @ 0x%08X, embedded in the kernel"
                  % img.initramfs_offset)
            print("              (so no separate -initrd is needed to reach userspace)")
        else:
            print("    rootfs  : no LZ4 cpio archive found")

    if img.members:
        if img.nonce:
            print("    nonce   : %r (%d bytes, in the clear)"
                  % (img.nonce.decode("latin-1", "replace"), len(img.nonce)))
        print("    members :")
        for m in img.members:
            print("      %-28s %12d bytes @ 0x%08X%s"
                  % (m.name, m.size, m.offset, "  [encrypted]" if m.encrypted else ""))
