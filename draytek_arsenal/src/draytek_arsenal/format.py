import hashlib

from draytek_arsenal.linux import DraytekLinux
from draytek_arsenal.draytek_format import Draytek
from draytek_arsenal.v3000 import V3000Image, looks_like_v3000
from draytek_arsenal import v3000
from kaitaistruct import KaitaiStream
from io import BytesIO

# RTOS images end with this tag followed by 32 lowercase hex characters: the
# MD5 of every byte preceding the tag.
IMAGE_MD5_TAG = b"DrayTekImageMD5\x00"
_MD5_HEX_LEN = 32


def verify_image_md5(data: bytes) -> tuple[bool, str, str] | None:
    """Check an image's self-describing MD5 trailer.

    Returns ``(ok, claimed, actual)``, or ``None`` when the image carries no
    trailer (older builds and the V3000 family do not).
    """
    tag = data.rfind(IMAGE_MD5_TAG)
    if tag < 0:
        return None

    start = tag + len(IMAGE_MD5_TAG)
    claimed = data[start:start + _MD5_HEX_LEN].decode("ascii", "replace")
    actual = hashlib.md5(data[:tag]).hexdigest()
    return claimed == actual, claimed, actual


def parse_firmware(filename: str,) -> Draytek | DraytekLinux | V3000Image:
    f = open(filename, 'rb')
    data = f.read()

    # V3000 family (Vigor 300B / 2960 / 3900): plain-text checksum header in
    # front of a ubinized UBI image. Checked first because its header is a
    # strict, cheap match and the image body can contain anything.
    if looks_like_v3000(data):
        f.close()
        return v3000.parse(data)

    if b"nonce" in data and b"enc_Image" in data:
        return DraytekLinux(data)

    has_dlm = b"DLM/1.0" in data

    try:
        return Draytek(has_dlm, KaitaiStream(BytesIO(data)))

    except Exception:
        # close file descriptor, then reraise the exception
        f.close()
        raise
