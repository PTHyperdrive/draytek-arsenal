"""Pure-Python LZO1X decompressor.

UBIFS compresses most data nodes with LZO1X, and ``python-lzo`` needs a C
toolchain that is often unavailable (notably on Windows), so we ship a
self-contained decoder instead.

This is a direct transliteration of the reference ``lzo1x_decompress`` from
minilzo/the Linux kernel. That routine is written with ``goto``s, so it is
reproduced here as an explicit label state machine -- keeping the shape
identical to the original is what makes it reviewable against the reference.

Decompression only; we never need to produce LZO.
"""

from __future__ import annotations

# Labels in the reference implementation.
_TOP, _FIRST_LITERAL_RUN, _MATCH, _COPY_MATCH, _MATCH_DONE, _MATCH_NEXT, _EOF = range(7)

M2_MAX_OFFSET = 0x0800


class LzoError(Exception):
    pass


def decompress(src: bytes, expected_size: int | None = None) -> bytes:
    """Decompress an LZO1X stream.

    ``expected_size`` is optional; when supplied it is enforced, which catches
    silent corruption that would otherwise surface much later.
    """
    n = len(src)
    if n == 0:
        return b""

    out = bytearray()
    ip = 0
    t = 0
    m_pos = 0

    def take_literals(count: int) -> None:
        """Copy ``count`` literal bytes from input to output."""
        nonlocal ip
        if ip + count > n:
            raise LzoError("input overrun in literal run")
        out.extend(src[ip:ip + count])
        ip += count

    def copy_from_match(count: int) -> None:
        """Copy ``count`` bytes from ``m_pos``, honouring overlap."""
        nonlocal m_pos
        if m_pos < 0 or m_pos >= len(out):
            raise LzoError(f"bad match position {m_pos} (out={len(out)})")
        end = m_pos + count
        if end <= len(out):
            out.extend(out[m_pos:end])
            m_pos = end
        else:
            for _ in range(count):
                out.append(out[m_pos])
                m_pos += 1

    def read_long_length(base: int) -> int:
        """Decode the zero-extended length encoding."""
        nonlocal ip
        length = 0
        if ip >= n:
            raise LzoError("input overrun in length")
        while src[ip] == 0:
            length += 255
            ip += 1
            if ip >= n:
                raise LzoError("input overrun in length")
        length += base + src[ip]
        ip += 1
        return length

    # --- entry: a first byte > 17 encodes a leading literal run ---
    if src[0] > 17:
        t = src[0] - 17
        ip = 1
        if t < 4:
            label = _MATCH_NEXT
        else:
            take_literals(t)
            label = _FIRST_LITERAL_RUN
    else:
        label = _TOP

    while True:
        if label == _TOP:
            if ip >= n:
                raise LzoError("input overrun")
            t = src[ip]; ip += 1
            if t >= 16:
                label = _MATCH
                continue
            if t == 0:
                t = read_long_length(15)
            take_literals(t + 3)
            label = _FIRST_LITERAL_RUN
            continue

        if label == _FIRST_LITERAL_RUN:
            if ip >= n:
                raise LzoError("input overrun")
            t = src[ip]; ip += 1
            if t >= 16:
                label = _MATCH
                continue
            m_pos = len(out) - (1 + M2_MAX_OFFSET) - (t >> 2) - (src[ip] << 2)
            ip += 1
            copy_from_match(3)
            label = _MATCH_DONE
            continue

        if label == _MATCH:
            if t >= 64:
                m_pos = len(out) - 1 - ((t >> 2) & 7) - (src[ip] << 3)
                ip += 1
                t = (t >> 5) - 1
                label = _COPY_MATCH
                continue
            elif t >= 32:
                t &= 31
                if t == 0:
                    t = read_long_length(31)
                if ip + 2 > n:
                    raise LzoError("input overrun in M3 distance")
                m_pos = len(out) - 1 - ((src[ip] | (src[ip + 1] << 8)) >> 2)
                ip += 2
                label = _COPY_MATCH
                continue
            elif t >= 16:
                m_pos = len(out) - ((t & 8) << 11)
                t &= 7
                if t == 0:
                    t = read_long_length(7)
                if ip + 2 > n:
                    raise LzoError("input overrun in M4 distance")
                m_pos -= (src[ip] | (src[ip + 1] << 8)) >> 2
                ip += 2
                if m_pos == len(out):
                    label = _EOF
                    continue
                m_pos -= 0x4000
                label = _COPY_MATCH
                continue
            else:
                m_pos = len(out) - 1 - (t >> 2) - (src[ip] << 2)
                ip += 1
                copy_from_match(2)
                label = _MATCH_DONE
                continue

        if label == _COPY_MATCH:
            copy_from_match(t + 2)
            label = _MATCH_DONE
            continue

        if label == _MATCH_DONE:
            # The trailing literal count lives in the second-to-last input byte.
            t = src[ip - 2] & 3
            label = _TOP if t == 0 else _MATCH_NEXT
            continue

        if label == _MATCH_NEXT:
            take_literals(t)
            if ip >= n:
                raise LzoError("input overrun")
            t = src[ip]; ip += 1
            label = _MATCH
            continue

        if label == _EOF:
            break

    if expected_size is not None and len(out) != expected_size:
        raise LzoError(f"size mismatch: got {len(out)}, expected {expected_size}")
    return bytes(out)
