"""Pure-Python LZ4 block decompressor.

DrayOS firmware sections are sequences of LZ4 blocks wrapped in a small
DrayTek container (see :mod:`draytek_arsenal.compression`). The ``lz4``
package is a compiled extension whose wheels routinely lag new CPython
releases, so -- as with :mod:`draytek_arsenal.lzo1x` -- we ship a
self-contained decoder and fall back to it when the C module is unavailable.

This implements the LZ4 *block* format only: a bare sequence of

    token | [extra literal length] | literals | offset | [extra match length]

with no frame header, no magic and no stored uncompressed size, which is what
``lz4.block.decompress(..., uncompressed_size=N)`` consumes.

Decompression only; repacking still requires the real ``lz4`` package.
"""

from __future__ import annotations

MIN_MATCH = 4
_EXTEND = 0xFF


class Lz4Error(Exception):
    pass


def _read_extended_length(src: bytes, ip: int, length: int) -> tuple[int, int]:
    """Consume a 255-chained length extension, returning (length, new ip)."""
    n = len(src)
    while True:
        if ip >= n:
            raise Lz4Error("truncated length extension at offset %d" % ip)
        b = src[ip]
        ip += 1
        length += b
        if b != _EXTEND:
            return length, ip


def decompress(src: bytes, expected_size: int | None = None) -> bytes:
    """Decompress a raw LZ4 block.

    ``expected_size`` is optional; when supplied it is enforced, which catches
    silent corruption that would otherwise surface much later.
    """
    n = len(src)
    if n == 0:
        return b""

    out = bytearray()
    ip = 0

    while ip < n:
        token = src[ip]
        ip += 1

        # Literals.
        literal_length = token >> 4
        if literal_length == 15:
            literal_length, ip = _read_extended_length(src, ip, literal_length)
        if literal_length:
            if ip + literal_length > n:
                raise Lz4Error(
                    "literal run of %d overruns input at offset %d"
                    % (literal_length, ip)
                )
            out += src[ip:ip + literal_length]
            ip += literal_length

        # The final sequence carries literals only and stops here.
        if ip == n:
            break
        if ip + 2 > n:
            raise Lz4Error("truncated match offset at offset %d" % ip)

        # Match.
        offset = src[ip] | (src[ip + 1] << 8)
        ip += 2
        if offset == 0:
            raise Lz4Error("zero match offset at offset %d" % (ip - 2))
        if offset > len(out):
            raise Lz4Error(
                "match offset %d reaches before the start of %d decoded bytes"
                % (offset, len(out))
            )

        match_length = token & 0x0F
        if match_length == 15:
            match_length, ip = _read_extended_length(src, ip, match_length)
        match_length += MIN_MATCH

        start = len(out) - offset
        if offset >= match_length:
            out += out[start:start + match_length]
        else:
            # Overlapping copy: LZ4 uses these as run-length encoding, so the
            # bytes must be produced one at a time as they become available.
            for i in range(start, start + match_length):
                out.append(out[i])

    if expected_size is not None and len(out) != expected_size:
        raise Lz4Error(
            "decompressed %d bytes, expected %d" % (len(out), expected_size)
        )

    return bytes(out)
