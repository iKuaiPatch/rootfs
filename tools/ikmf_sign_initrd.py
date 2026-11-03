#!/usr/bin/env python3
"""Append a 0x194 IKMF trailer so official ik_core MD5 of a plaintext xz initrd passes.

ik_core hashes k7p9vn-0x194 bytes at j4m2zc, then:

    md1 = MD5(body)
    md2 = MD5(md1[8:16] + md1[0:8] + dword_at_trailer+0x10)
    md3 = MD5(md2)

and compares md3 to trailer[:16]. Pack xz-skip images with this 0x194 trailer
(not the official 0x294, which includes an extra 256-byte RSA blob ik_core
does not consume). Verified on 4.0.311 x64 with unmodified ik_core.ko.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

TRAILER_LEN = 0x194
IKMF = b"IKMF"


def md_chain(body: bytes, dword: bytes) -> bytes:
    if len(dword) != 4:
        raise ValueError("dword must be 4 bytes")
    md1 = hashlib.md5(body).digest()
    md2 = hashlib.md5(md1[8:16] + md1[0:8] + dword).digest()
    return hashlib.md5(md2).digest()


def make_trailer(body: bytes, dword: bytes = b"\xe9\xdb\xb8\xab") -> bytes:
    tr = bytearray(TRAILER_LEN)
    tr[0:16] = md_chain(body, dword)
    tr[16:20] = dword
    tr[20:24] = IKMF
    struct.pack_into("<I", tr, 24, 3)
    struct.pack_into("<I", tr, 28, 0x80)
    struct.pack_into("<Q", tr, 36, len(body))
    struct.pack_into("<Q", tr, 44, len(body))
    return bytes(tr)


def sign_initrd(data: bytes) -> bytes:
    if data[:6] != b"\xfd7zXZ\x00":
        raise SystemExit("input is not an xz stream")
    if len(data) >= TRAILER_LEN + 4 and data[-TRAILER_LEN + 20 : -TRAILER_LEN + 24] == IKMF:
        data = data[:-TRAILER_LEN]
    return data + make_trailer(data)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input_xz")
    ap.add_argument("output_xz")
    args = ap.parse_args()
    src = Path(args.input_xz)
    dst = Path(args.output_xz)
    out = sign_initrd(src.read_bytes())
    dst.write_bytes(out)
    body = len(out) - TRAILER_LEN
    print(f"[ikmf] signed {src} -> {dst} body={body} trailer={TRAILER_LEN}")


if __name__ == "__main__":
    main()
