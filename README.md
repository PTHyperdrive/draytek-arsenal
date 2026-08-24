# Draytek Arsenal: Observability and hardening toolkit for Draytek edge devices.

> **Fork note.** This fork adds support for the **V3000 family** — Vigor 300B, Vigor 2960
> and Vigor 3900 — which upstream did not handle. These models use neither the MIPS RTOS
> container nor the ChaCha20 `enc_Image` container: their `.all` files are a 48-byte
> plain-text checksum header in front of an ordinary ubinized UBI image, and **nothing in
> them is encrypted**. See [`docs/V3000_FORMAT.md`](docs/V3000_FORMAT.md) for the full
> format description and how it was confirmed, and the
> [`extract_v3000`](#extract_v3000) command below.
>
> Also included: a dependency-free UBI reader (`ubi.py`), a read-only UBIFS reader
> (`ubifs.py`), a pure-Python LZO1X decompressor (`lzo1x.py`, so no C toolchain is
> needed for UBIFS), and a fix so that one command's missing optional dependency no
> longer disables the entire CLI.

Advanced attackers are increasingly choosing edge devices as targets. However, these devices are controlled by closed-source software known as firmware, often distributed in a proprietary format. This is an added difficulty for defenders and researchers, who must understand how to extract firmware to assess its security.

This is more than just a hypothetical scenario, as we discovered recently when a client was compromised. With Draytek equipment at the edge of their infrastructure, the natural question was: Could this be the attackers' entry point? Over 500k Draytek devices are exposed to the Internet. Yet, no working tool exists to extract their firmware and assist researchers and defenders working with these devices.

During our assessment, we reverse-engineered Draytek's firmware format, which contains a bootloader, a compressed RTOS kernel, and two filesystems. Through our investigation, we developed tools to extract these components, unveiling the real-time operating system's capability to load code modules dynamically. These modules are loaded from one of the filesystems in the firmware image during boot but can also be loaded while the system is running and stored in a separate filesystem in flash memory. An attacker can exploit this feature to achieve persistence by loading a module that remains active even after a reboot or firmware upgrade, and the end-user does not have a way to detect this type of attack. Consequently, we developed our own module to check the integrity of loaded modules in memory, mitigating this potential threat.

In our pursuit of a more secure internet, we are making this set of tools accessible to the community, enabling observability, hardening, transparency, and vulnerability research on Draytek edge devices

## Presentation
This tool was developed as part of a research project that was presented at [DEFCON HHV and La Villa Hacker](https://defcon.org/html/defcon-32/dc-32-creator-talks.html#54642). You can find the slides and PoC videos [here](https://drive.google.com/drive/folders/1G-fvAntkuCg9Hu_MeMSdYTCd7KAlIywk?usp=sharing). 

## Note
We initially developed this as an internal tool. It was just a set of scripts, but it showed great potential, prompting us to make it open-source. Since then, we have been working to integrate these scripts into the Python package you will find in this repo and make them compatible with other device models.

## Get started ##

__Requirements:__

* Python3
* Docker (Optional)

### Installation ###

(Optional) Create and activate python virtual environment:
```bash
$ python3 -m virtualenv .venv
$ source .venv/bin.activate
```

Install `draytek_arsenal`:
```bash
$ cd draytek_arsenal
$ python3 -m pip install -r requirements.txt
$ python3 -m pip install .
```

Test the installation:
```
$ python3 -m draytek_arsenal
```

### Install as developer ###

This installation will be affected by local code changes
```
$ python3 -m pip install -e .
```

### Mips-tools ###

Some commands as `mips_compile` and `mips_merge` needs a complementary Docker image in order to work.  
If it has not been downloaded this error message is shown:
```
[x] Image 'draytek-arsenal' not found. Please build or download the image.
```

You could download the image with the following command:

```bash
$ docker pull ghcr.io/infobyte/draytek-arsenal:main
```

Or build it with:
```bash
$ docker build -t draytek-arsenal ./mips-tools
```


## Usage ##

`draytek-arsenal` is a set of scripts collected in a python package. So, to use it you should select a command:

```
usage: draytek-arsenal [-h] [command] args..
```

Some of the commands are:


### parse_firmware ###

Parse and show information of a Draytec firmware.

```
usage: parse_firmware [-h] firmware

positional arguments:
  firmware    Path to the firmware

options:
  -h, --help  show this help message and exit
```

### extract small business ###

Command used to extract and decompress Draytek running an RTOS.

```
usage: extract_rtos [-h] [--rtos RTOS] [--fs FS] [--dlm DLM] [--dlm-key1 DLM_KEY1]
                  [--dlm-key2 DLM_KEY2]
                  firmware

positional arguments:
  firmware              Path to the firmware

options:
  -h, --help            show this help message and exit
  --rtos RTOS, -r RTOS  File path where to extract and decompress the RTOS
  --fs FS, -f FS        Directory path where to extract and decompress the File
                        System
  --dlm DLM, -d DLM     Directory path where to extract and decompress the DLMs
  --dlm-key1 DLM_KEY1   First key used to decrypt DLMs
  --dlm-key2 DLM_KEY2   First key used to decrypt DLMs
```

### extract linux ###

Command used to extract and decompress Draytek running linux

```
usage: extract_linux [-h] [--fs FS] --key KEY firmware

positional arguments:
  firmware        Path to the firmware

options:
  -h, --help      show this help message and exit
  --fs FS, -f FS  Directory path where to extract and decompress the File System
  --key KEY       Key used to decrypt
```

### extract_v3000 ###

Parse, verify and extract V3000-family firmware — **Vigor 300B, Vigor 2960 and Vigor
3900** (`.all`, `.rst`, `.cv3`, `.cx2`, `.ota`).

There is no `--key`: these images are not encrypted. The container is a plain-text
MD5 + CRC-32 header over a ubinized UBI image holding a single `rootfs` UBIFS volume.

```
usage: extract_v3000 [-h] [--fs FS] [--ubi UBI] [--volume VOLUME]
                     [--signature SIGNATURE] [--list] [--json] [--no-verify]
                     firmware

positional arguments:
  firmware              Path to the firmware image

options:
  -h, --help            show this help message and exit
  --fs FS, -f FS        Directory to extract the root filesystem into
  --ubi UBI             Write the raw ubinized UBI image to this path
  --volume VOLUME       Write the raw UBIFS volume image to this path
  --signature SIGNATURE Write the OTA RSA signature blob to this path (.ota input only)
  --list, -l            List filesystem contents
  --json                Emit image metadata as JSON
  --no-verify           Skip UBIFS node CRC verification
```

Example:

```bash
$ python3 -m draytek_arsenal extract_v3000 Vigor300B_v1.5.1.all --fs ./rootfs
[+] Draytek V3000 container
    machine type : V3000  (Vigor 300B, firmware (.all, keeps configuration))
    payload      : 40,370,182 bytes (machine-type line + UBI image)
    UBI image    : 40,370,176 bytes
    MD5          : 133ff3fc394242703c221d477cc1cb0f OK
    CRC32        : d1977fdf OK
    encryption   : none (payload is a plain ubinized UBI image)

[*] UBI: PEB=0x20000 LEB=0x1f800 PEBs=308 image_seq=0x23f218b5
[*] version string in EC header padding: '1.5.1_RC2'
[*] volume id=0 name='rootfs' type=dynamic LEBs=306

[*] parsing UBIFS in volume 'rootfs'...
[*] UBIFS fmt v4, default compression lzo, uuid f9fa43ec8e214ca6862b8a69faac4c60
[*] 25,769 nodes (0 bad CRC), 3,143 inodes
[*] 3,142 directory entries reachable from root
[+] extracted to ./rootfs
    dirs=164 files=2553 symlinks=425 special=0 skipped=0
```

`parse_firmware` also recognises these images and reports them as `type: V3000`.

Repacking is supported programmatically — `v3000.build(ubi_image, machine_type)`
recomputes both checksums exactly as Draytek's own build script does, so a modified
image passes the stock updater's validation:

```python
from draytek_arsenal import v3000

img = v3000.parse(open("Vigor300B_v1.5.1.all", "rb").read())
open("repacked.all", "wb").write(v3000.build(img.ubi, img.machine_type))
```

### extract_v3910 ###

Unpack and **emulate** the ARM64 Linux family — **Vigor 3910, 2962 and 3912**
(`.all`, `.sfw`). These are neither the MIPS RTOS container nor the V3000 UBI
container: they are a DrayTek header over a Marvell/Cavium OCTEON TX boot chain
— ATF, U-Boot, board device trees, an ARM64 Linux `Image`, and a root
filesystem. DrayOS runs as a *process* on that Linux rather than being the
kernel.

Two generations, under two container headers (`0x06020106` and `6216`):

- **3.9.x and earlier — in the clear, and directly bootable.** The kernel
  carries its root filesystem as an embedded initramfs, so no `-initrd` is
  needed to reach userspace.
- **4.x — ChaCha20 encrypted.** Members (`vmlinuz.enc`, `rootfs.uboot.img.enc`,
  `flash-image.bin.enc`, a `.dtb.enc`) are located and listed, and the 12-byte
  nonce is read from the clear, but the 256-bit key lives in the bootloader and
  is not in the image. Nothing to boot.

```
usage: extract_v3910 [-h] [--kernel KERNEL] [--dtb-dir DTB_DIR] [--list]
                     [--rootfs ROOTFS] [--json] [--qemu] [--run]
                     [--memory MEMORY] [--cpu CPU]
                     [--cmdline CMDLINE]
                     firmware
```

Inspect an image:

```console
$ python -m draytek_arsenal extract_v3910 v3910_3971.all --list
[+] v3910_3971.all
    version : 3.9.7.1_RC1
    type    : plain ARM64 Linux
    kernel  : ARM64 Image @ 0x00504030, text_offset 0x80000, little-endian
              image_size 44011520 bytes (runtime footprint, includes BSS)
    dtbs    : 47 board device trees
    rootfs  : LZ4 cpio initramfs @ 0x00EE3C48, embedded in the kernel
              (so no separate -initrd is needed to reach userspace)
```

Unpack the root filesystem for static analysis:

```console
$ python -m draytek_arsenal extract_v3910 v3910_3971.all --rootfs rootfs/
[*] Initramfs: LZ4 legacy frame @ 0x00EE3C48
[*] Decompressed to 79824384 bytes of cpio
[+] Root filesystem unpacked to rootfs/
    430 files (79692656 bytes), 88 dirs, 401 symlinks
```

The archive is a cpio in an **LZ4 legacy frame** — magic `02214c18`, then
`[u32le block_length][block]` — not the modern LZ4 frame format. Searching for
the cpio magic directly does not find it: the hits are the kernel's own
`"no cpio magic"` error string and literals inside compressed data. Locate the
LZ4 frame and confirm by what the first block decompresses to.

Decompression uses the bundled pure-Python `lz4_block`, so this needs no
compiled `lz4`. Path traversal is refused; symlinks are recreated where the
platform allows and otherwise recorded in `symlinks.txt`.

What comes out is the full DrayOS userland, including
`firmware/vqemu/sohod64.bin` (the DrayOS binary itself), `sbin/chacha20` (the
firmware decryptor — it contains `expand 32-byte k`), DrayTek's own QEMU launch
scripts under `firmware/`, and a copy of `usr/bin/qemu-system-aarch64`: the
device emulates DrayOS on itself.

Extract the kernel and boot it:

```console
$ python -m draytek_arsenal extract_v3910 v3910_3971.all --kernel Image --run
...
[    0.000000] Linux version 4.9.0-OCTEONTX_SDK_6_2_0_p3_build_38 (jenkins@cavium-autobuild)
[    0.737651] Freeing unused kernel memory: 32384K
Vigor3910 login:
Boot DrayOS with MEMSIZE -m 512
```

`--qemu` prints the command instead of running it.

Three things worth knowing:

- The kernel is carved from its header to the end of the image. The ARM64
  header's `image_size` is the *runtime* footprint including BSS — on a real
  3910 it reads 44 MB against a 43 MB file — so it cannot be used as a length.
  Trailing bytes are harmless; truncation is not.
- **Do not pass a board device tree to `-M virt`.** `--dtb-dir` writes them out
  for inspection, but they describe OCTEON TX hardware QEMU does not emulate.
  `virt` builds its own tree, and the kernel is multi-platform, so it happily
  uses virt's PL011 and PSCI instead. Supplying the real tree makes the boot
  fail earlier, not work better.
- `earlycon` in the default command line is load-bearing: without it there is no
  output until the console driver probes, which on foreign hardware may be never.

What you get is a real DrayTek kernel on synthetic hardware — genuine build,
genuine userspace, but the platform underneath is QEMU's. Enough to reach a
login prompt and run DrayOS as a process; not a faithful 3910. Hardware drivers
find no devices, and DrayOS coredumps when it reaches for `/dev/mtd0`.

### scripts/fw_triage.py ###

Standalone triage for an unknown firmware image, answering the question worth
asking before you write any parser: **is this actually encrypted?** Getting that
wrong sends you looking for a key that may not exist.

It reports an entropy profile, a magic-value scan and any plaintext strings in the
header, then gives a conservative verdict. Stdlib only, and nothing about it is
Draytek-specific.

```
usage: fw_triage.py [-h] [--head HEAD] [--strings-window STRINGS_WINDOW]
                    [--min-string MIN_STRING]
                    firmware [firmware ...]
```

```bash
$ python3 scripts/fw_triage.py Vigor300B_v1.5.1.all
-- entropy profile (1 MiB windows, 0-8 bits/byte) --
  ▁▅███████████████▅▆▇███████▇████▇███▇▇▅

-- verdict --
  NOT ENCRYPTED -- 27390 plaintext magic value(s) found. Structured data cannot survive a cipher.
```

The distinction it leans on: encrypted data pins flat near 8.0 bits/byte across the
whole image, while compressed data lands around 7.0–7.9 and *varies* between
windows. Plaintext ELF headers or filesystem superblocks settle it outright — they
cannot survive a cipher. Magic values shorter than four bytes collide by chance in
any large file, so they are reported but excluded from the verdict.

### dlm_hash ###

Get the hash of a DLM module.

```
usage: dlm_hash [-h] [-c] dlm

positional arguments:
  dlm         Path to the dlm

options:
  -h, --help  show this help message and exit
  -c          Print as .c code
```

### find_loading_addr ###

Find the address where the RTOS if loaded with the first jump instruction.

```
usage: find_loading_addr [-h] rtos

positional arguments:
  rtos        Path to the rtos

options:
  -h, --help  show this help message and exit
```

### find_endianness ###

Checks if the RTOS is little or big endian.

```
usage: find_endianness [-h] rtos

positional arguments:
  rtos        Path to the rtos

options:
  -h, --help  show this help message and exit
```

### mips_compile ###

Compile MIPS relocatable binary (used for DLMs).

```
usage: mips_compile [-h] output [input ...]

positional arguments:
  output      Output file
  input       Output file

options:
  -h, --help  show this help message and exit
```

### mips_merge ###

Merge two ELF MIPS relocatable files.

```
usage: mips_merge [-h] first_input second_input output

positional arguments:
  first_input   First input file
  second_input  Second input file
  output        Output file

options:
  -h, --help    show this help message and exit
```
