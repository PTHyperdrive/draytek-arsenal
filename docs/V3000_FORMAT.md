# The Draytek "V3000" firmware format (Vigor 300B / 2960 / 3900)

This documents the container used by Draytek's V3000-family firmware, how it was
confirmed, and what is inside it.

**Headline: these images are not encrypted.** There is no key to recover. A `.all`
file is a 48-byte ASCII checksum header followed byte-for-byte by an ordinary
ubinized UBI image. Anything that reads UBI can read it once the header is removed.

This matters because the two container formats already handled by this toolkit —
the MIPS RTOS container and the ChaCha20 `enc_Image` container used by Linux-based
models like the Vigor 2860/2925 — do *not* apply here, and `extract_linux --key ...`
will never work on a Vigor 300B no matter what key is supplied.

---

## 1. Container layout

```
offset  size  contents
------  ----  -----------------------------------------------------------
0x00      32  lowercase hex MD5 of the payload
0x20       1  '\n'
0x21       8  lowercase hex CRC-32 of the payload
0x29       1  '\n'
0x2a       5  machine type, e.g. "V3000"
0x2f       1  '\n'
0x30     ...  ubinized UBI image, to end of file
```

The header is always exactly `0x30` bytes, because every machine-type tag is five
characters.

### The checksums cover the machine-type line

This is the one detail that is easy to get wrong. Both checksums are computed over
`data[0x2a:]` — the **machine-type line together with the UBI image** — not over the
UBI image alone. Hashing from `0x30` will not reproduce the stored digest.

* MD5: standard MD5, lowercase hex.
* CRC-32: standard CRC-32 (the zlib/PKZIP one, with final inversion), lowercase hex.
  This is *not* the kernel-flavoured CRC-32 used inside UBI and UBIFS headers.

In Python:

```python
payload = data[0x2a:]
md5   = hashlib.md5(payload).hexdigest()
crc32 = f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}"
```

### Machine types

The tag identifies both the model and what the updater should do with the image.

| Tag     | Model      | Meaning                                     |
| ------- | ---------- | ------------------------------------------- |
| `V3000` | Vigor 300B | firmware, keeps configuration (`.all`)      |
| `V3010` | Vigor 300B | firmware, resets to factory defaults (`.rst`)|
| `V3100` | Vigor 300B | firmware (`.cv3`)                           |
| `V3001` | Vigor 300B | bootloader (u-boot)                         |
| `X2000` | Vigor 2960 | firmware, keeps configuration (`.all`)      |
| `X2010` | Vigor 2960 | firmware, resets to factory defaults (`.rst`)|
| `X2100` | Vigor 2960 | firmware (`.cx2`)                           |
| `X2001` | Vigor 2960 | bootloader (u-boot)                         |
| `39000` | Vigor 3900 | firmware, keeps configuration (`.all`)      |
| `39010` | Vigor 3900 | firmware, resets to factory defaults (`.rst`)|
| `39001` | Vigor 3900 | bootloader (u-boot)                         |

So `.all` and `.rst` for the same release differ **only** in this five-byte tag and
the two checksums that cover it — the UBI payload is identical.

Note that a bootloader `.all` uses the same container but wraps `u-boot.bin`
directly rather than a UBI image.

---

## 2. `.ota` files

An `.ota` file is the same image with a **256-byte prefix**, which is the size of an
RSA-2048 signature:

```
offset  size  contents
------  ----  -----------------------------------------------------------
0x00     256  RSA-2048 signature blob
0x100    ...  the .all container, byte-identical
```

Strip the first 256 bytes and you have the `.all`. Confirmed by direct comparison:
for the v1.5.1 release, `ota[256:]` is byte-identical to `Vigor300B_v1.5.1.all`
(both MD5 `13fb9e75e4bcc92bdac1633942636443`).

The signature is a detached integrity/authenticity check consumed by the updater;
it is not encryption, and the payload behind it is plaintext. Recovering the public
key that validates it would require the verifying binary from the rootfs — which the
extraction below gives you.

---

## 3. Where the format came from

The layout is not guesswork. Draytek publishes the GPL source for these devices, and
the top-level `build` script in the V300B GPL release assembles the image in the
clear:

```sh
# Create .all file, insert CRC32 and MD5 checksum in header
echo $MACHINE_TYPE_FW > ${TOPDIR}/bin/machine_type
cat ${TOPDIR}/bin/machine_type ${TOPDIR}/bin/root.ubifs-ubinized > ${TOPDIR}/bin/V3K9_unchecked.all

CHECK_SUM_MD5=`md5sum   ${TOPDIR}/bin/V3K9_unchecked.all | awk '{print $1}'`
CHECK_SUM_CRC32=`mkcrc32 ${TOPDIR}/bin/V3K9_unchecked.all | awk '{print $1}'`

echo $CHECK_SUM_MD5   > ${TOPDIR}/bin/checksum_md5
echo $CHECK_SUM_CRC32 > ${TOPDIR}/bin/checksum_crc32

cat ${TOPDIR}/bin/checksum_md5 ${TOPDIR}/bin/checksum_crc32 \
    ${TOPDIR}/bin/V3K9_unchecked.all > ${TOPDIR}/bin/${BUILD_FW_NAME}
```

`echo` supplies each trailing newline, which is where the three `\n` separators come
from, and `cat` explains why the checksums include the machine-type line: it is
already part of `V3K9_unchecked.all` when the digests are taken. The same block is
repeated in the script for `.rst`, `.cx2`/`.cv3` and the bootloader with a different
`MACHINE_TYPE_*`.

The GPL release also ships `ubifs_args.ini`, the ubinize config:

```ini
[ubifs]
mode=ubi
vol_id=0
vol_size=61740KiB
vol_type=dynamic
vol_name=rootfs
```

### Verification

The implementation was checked against three stock images. All three reproduce both
stored checksums exactly, and repacking the untouched UBI payload returns the
original file byte-for-byte:

| Image                    | Machine | Stored MD5                         | Stored CRC-32 | Verdict |
| ------------------------ | ------- | ---------------------------------- | ------------- | ------- |
| `V300B_r2825.all` (1.0.7) | `V3000` | `e1cf0e6e7a60189b55292057ae7afd2f` | `c605f9e9`    | OK      |
| `Vigor300B_v1.5.1.all`    | `V3000` | `133ff3fc394242703c221d477cc1cb0f` | `d1977fdf`    | OK      |
| `V300B_1516.all` (1.5.1.6)| `V3000` | `b8e3741540a4743fdc7e37203d966463` | `2bda4eaa`    | OK      |

---

## 4. Inside the UBI image

Standard UBI, readable with `ubireader`, or with this repo's `ubi.py`:

* PEB (physical erase block) size `0x20000` (128 KiB)
* `vid_hdr_offset` `0x200`, `data_offset` `0x800`, so LEB size is `0x1F800` (129,024 B)
* One data volume: **id 0, name `rootfs`, dynamic**, plus the standard layout volume
  at id `0x7FFFEFFF`
* Image size is always a whole number of PEBs (203, 307 and 308 in the images above)

One Draytek-specific quirk: the **firmware version string is stashed in the UBI EC
header's `padding2` field** — `1.0.7_RC2`, `1.5.1_RC2`, `1.5.1.6RC1`. Standard UBI
leaves that region zeroed, so it is a cheap way to identify a build. A byte in
`padding1` also varies between releases (`00 31 00` on 1.0.7, `00 31 03` on 1.5.x).

Note that UBI and UBIFS headers use the **kernel** CRC-32 — seeded with `0xFFFFFFFF`
and with *no* final inversion — which is the standard CRC-32 XORed with
`0xFFFFFFFF`. Using the wrong variant here makes every node look corrupt.

---

## 5. Inside the rootfs volume

The `rootfs` volume is a **UBIFS** filesystem:

* format version 4, fanout 8, `min_io_size` 2048, LEB size 129,024
* **default compression LZO** (LZO1X); a minority of data nodes are stored
  uncompressed
* v1.5.1 contains 25,769 nodes — 16,008 data, 3,143 inode, 3,142 dentry, 3,187 index,
  285 padding — all passing CRC

Contents are a **Mindspeed Comcerto 1000 OpenWrt** build, ARM32 little-endian
(`EM_ARM`, ELF32). `/etc/banner` reads:

```
 M I N D S P E E D  Technologies - Build v6.0 for Comcerto
```

which lines up with the GPL tree's `build_dir/linux-2.6-comcerto1000` paths.

Extracted from v1.5.1: 164 directories, 2,553 regular files, 425 symlinks
(59 MB total). Notable contents:

| Path                      | What it is                          |
| ------------------------- | ----------------------------------- |
| `/boot/uImage`            | the Linux kernel (2.1 MB)           |
| `/lib/firmware/msp.axf`   | Comcerto DSP/packet-engine firmware |
| `/www/`                   | the web UI (incl. `ajax.zip`, 5.8 MB)|
| `/usr/sbin/samba_multicall` | Samba                             |
| `/usr/sbin/bgpd`          | Quagga routing daemon               |
| `/usr/lib/libcrypto.so.1.0.0` | OpenSSL                         |
| `/bin/busybox`            | BusyBox                             |
| `/usr/bin/clish`          | the CLI shell login shells drop into |

`/usr/sbin` and `/www` are where the proprietary, non-GPL parts live — including
whatever validates the `.ota` RSA signature. That is the place to look next if you
want the update-verification public key.

---

## 6. How to extract, by hand

If you would rather not use this toolkit:

```bash
# 1. Strip the 48-byte header (and, for .ota, the 256-byte signature first)
dd if=Vigor300B_v1.5.1.all of=fw.ubi bs=1 skip=48

# 2. Read the UBI image
ubireader_extract_images fw.ubi      # -> rootfs volume image
ubireader_extract_files  fw.ubi      # -> the whole filesystem

# 3. Verify you did not corrupt anything
#    (checksums cover the machine-type line, so start at 0x2a, not 0x30)
tail -c +43 Vigor300B_v1.5.1.all | md5sum
head -c 32  Vigor300B_v1.5.1.all
```

`tail -c +43` is `0x2a + 1` because `tail -c +N` is 1-indexed.

With this toolkit it is one command:

```bash
python3 -m draytek_arsenal extract_v3000 Vigor300B_v1.5.1.all --fs ./rootfs
```

---

## 7. Repacking

Because the header is just MD5 + CRC-32 with no secret, a modified image can be
resealed so the stock updater accepts it:

```python
from draytek_arsenal import v3000
img = v3000.parse(open("Vigor300B_v1.5.1.all", "rb").read())
open("repacked.all", "wb").write(v3000.build(modified_ubi, img.machine_type))
```

The `.ota` RSA-2048 signature is a different matter — that one cannot be forged
without Draytek's private key. Whether a given device requires a valid signature, or
accepts an unsigned `.all` through the web UI, depends on the model and firmware
version and is worth checking before relying on either path.
