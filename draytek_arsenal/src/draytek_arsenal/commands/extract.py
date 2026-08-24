from typing import Any, Dict, List
from draytek_arsenal.commands.base import Command
from draytek_arsenal.format import parse_firmware, verify_image_md5
from draytek_arsenal.compression import Lz4
from draytek_arsenal.fs import PFSExtractor
from os import path
from struct import pack
import tempfile
import os

HEADER_SIZE = 0x100


class ExtractCommand(Command):
    @staticmethod
    def name() -> str:
        return "extract_rtos"


    @staticmethod
    def args() -> List[Dict[str, Any]]:
        return [
            {"flags": ["firmware"], "kwargs": {"type": str, "help": "Path to the firmware"}},
            {
                "flags": ["--rtos", "-r"],
                "kwargs": {
                    "type": str,
                    "help": "File path where to extract and decompress the RTOS",
                    "required": False
                }
            },
            {
                "flags": ["--fs", "-f"],
                "kwargs": {
                    "type": str,
                    "help": "Directory path where to extract and decompress the File System",
                    "required": False
                }
            },
            {
                "flags": ["--dlm", "-d"],
                "kwargs": {
                    "type": str,
                    "help": "Directory path where to extract and decompress the DLMs",
                    "required": False
                }
            },
            {
                "flags": ["--header"],
                "kwargs": {
                    "type": str,
                    "help": "File path where to write the 0x100-byte image header",
                    "required": False
                }
            },
            {
                "flags": ["--bootloader", "-b"],
                "kwargs": {
                    "type": str,
                    "help": "File path where to write the raw bootloader on its own",
                    "required": False
                }
            },
            {
                "flags": ["--dlm-key1"],
                "kwargs": {
                    "type": str,
                    "help": "First key used to decrypt DLMs",
                    "required": False
                }
            },
            {
                "flags": ["--dlm-key2"],
                "kwargs": {
                    "type": str,
                    "help": "First key used to decrypt DLMs",
                    "required": False
                }
            },
        ]


    @staticmethod
    def description() -> str:
        return "Command used to extract and decompress Draytek RTOS packages"

  
    @staticmethod
    def _prepare_output(file_path: str) -> bool:
        """Make sure a file output can be written, creating its directory.

        A bare filename has an empty dirname, and ``isdir("")`` is False, so
        naively testing the dirname rejects the most natural way to invoke the
        command. Treat that as the working directory.
        """
        parent = path.dirname(file_path) or os.curdir
        if path.isdir(parent):
            return True

        try:
            os.makedirs(parent)
            return True
        except OSError as exc:
            print(f"[x] Cannot write {file_path}: {exc}")
            return False


    @staticmethod
    def _extract_pfs(data: bytes, out_dir: str, extractor: PFSExtractor) -> None:
        """Run a PFS archive held in memory through PFSExtractor.

        The extractor takes a path, and Windows refuses to reopen a still-open
        NamedTemporaryFile by name, so stage the blob inside a temp directory
        instead of a temp file.
        """
        if not path.exists(out_dir):
            os.makedirs(out_dir)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = path.join(tmp_dir, "pfs.bin")
            print(f"[*] Writing decompressed FS to tmp file: {tmp_path}")
            with open(tmp_path, "wb") as tmp_fs:
                tmp_fs.write(data)

            extractor.extract(tmp_path, out_dir)


    @staticmethod
    def execute(args) -> None:
        fw_struct = parse_firmware(args.firmware)

        with open(args.firmware, "rb") as fh:
            raw = fh.read()

        checked = verify_image_md5(raw)
        if checked is None:
            print("[*] Image carries no DrayTekImageMD5 trailer, skipping check")
        elif checked[0]:
            print(f"[+] Image MD5 {checked[1]} verified")
        else:
            print(f"[x] Image MD5 mismatch: header says {checked[1]}, computed {checked[2]}")

        if (args.rtos is None and args.dlm is None and args.fs is None
                and args.header is None and args.bootloader is None):
            print(f"[x] Nothing to extract. Please set some extraction flag.")

        if args.header is not None and ExtractCommand._prepare_output(args.header):
            with open(args.header, "wb") as output_file:
                output_file.write(raw[:HEADER_SIZE])
            print(f"[+] Header extracted in {args.header}")

        if args.bootloader is not None and ExtractCommand._prepare_output(args.bootloader):
            # bootloader.data keeps the A55AA55A end marker as its last word;
            # everything before it is the raw MIPS the RTOS is appended to.
            boot = b"".join(pack(">I", word) for word in fw_struct.bin.bootloader.data[:-1])
            with open(args.bootloader, "wb") as output_file:
                output_file.write(boot)
            print(f"[+] Bootloader extracted in {args.bootloader} ({len(boot)} bytes)")

        if args.rtos is not None:
            print("[+] Extracting RTOS from firmware")

            if fw_struct.bin.rtos.rtos_size != len(fw_struct.bin.rtos.data):
                print(f"[x] Data length ({len(fw_struct.bin.rtos.data)}) doesn't match with the header length ({fw_struct.bin.rtos.rtos_size})")

            elif ExtractCommand._prepare_output(args.rtos):
                unstructured_bootloader = b"".join([pack(">I", integer) for integer in fw_struct.bin.bootloader.data[:-1]])

                lz4 = Lz4()
                decompressed_rtos = lz4.decompress(fw_struct.bin.rtos.data)
                with open(args.rtos, "wb") as output_file:
                    output_file.write(unstructured_bootloader + decompressed_rtos)

                print(f"[+] RTOS extracted in {args.rtos}")

        if args.dlm is not None:

            if not fw_struct.has_dlm:
                print(f"[*] Skiping DLMs extraction: the file does not have the magic") 

            elif args.dlm_key1 is None or args.dlm_key2 is None:
                print(f"[x] One or more keys are not provided")

            else:
                print("[+] Extracting DLMs from firmware")

                ExtractCommand._extract_pfs(
                    b"DLM/1.0" + fw_struct.bin.dlm.data,
                    args.dlm,
                    PFSExtractor(
                        bytes.fromhex(args.dlm_key1),
                        bytes.fromhex(args.dlm_key2)
                    ),
                )

                print(f"[+] DLMs extracted to {args.dlm}")


        if args.fs is not None:
            print("[+] Extracting FS from firmware")

            lz4 = Lz4()
            ExtractCommand._extract_pfs(
                lz4.decompress(fw_struct.web.data), args.fs, PFSExtractor()
            )

            print(f"[+] fs extracted to {args.fs}")

        print("[*] All done..")

