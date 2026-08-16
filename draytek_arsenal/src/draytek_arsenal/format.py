from draytek_arsenal.linux import DraytekLinux
from draytek_arsenal.draytek_format import Draytek
from draytek_arsenal.v3000 import V3000Image, looks_like_v3000
from draytek_arsenal import v3000
from kaitaistruct import KaitaiStream
from io import BytesIO


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
