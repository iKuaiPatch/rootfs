#!/usr/bin/env python3
"""Patch 4.0.306+ x64 vmlinuz so a plaintext xz initrd boots and ik_core MD5 passes.

When the ramdisk is already xz, jump past IKMF decrypt to unxz. Before that
jump, copy the mapped initrd into j4m2zc/k7p9vn (the two kernel globals
ik_core hashes). Cave sits in the IKMF-parse bytes this jump skips, not at
the unxz fallthrough. Recompresses the bzImage payload; lc=4 if lc=3 grows
past payload_size.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from patch_vmlinuz import (  # noqa: E402
    find_payload,
    parse_xz_params,
    xz_compress,
    xz_decompress,
)

SKIP_SITE = bytes.fromhex("48833d")
SKIP_TAIL = bytes.fromhex("ffff0f85")
XOR_ECX6 = bytes.fromhex("31c0b906000000")
INITRD_IMAGE = b"/initrd.image"


def elf_file_of(vmlinux: bytes, va: int) -> int | None:
    e_phoff = struct.unpack_from("<Q", vmlinux, 32)[0]
    e_phentsize = struct.unpack_from("<H", vmlinux, 54)[0]
    e_phnum = struct.unpack_from("<H", vmlinux, 56)[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", vmlinux, o)[0]
        if p_type != 1:
            continue
        p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from("<QQQQ", vmlinux, o + 8)
        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None


def elf_va(vmlinux: bytes, file_off: int) -> int:
    e_phoff = struct.unpack_from("<Q", vmlinux, 32)[0]
    e_phentsize = struct.unpack_from("<H", vmlinux, 54)[0]
    e_phnum = struct.unpack_from("<H", vmlinux, 56)[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", vmlinux, o)[0]
        if p_type != 1:
            continue
        p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from("<QQQQ", vmlinux, o + 8)
        if p_offset <= file_off < p_offset + p_filesz:
            return p_vaddr + (file_off - p_offset)
    raise SystemExit(f"no ELF mapping for {file_off:#x}")


def _shdrs(vmlinux: bytes) -> list[tuple[str, int, int, int]]:
    e_shoff = struct.unpack_from("<Q", vmlinux, 40)[0]
    e_shentsize = struct.unpack_from("<H", vmlinux, 58)[0]
    e_shnum = struct.unpack_from("<H", vmlinux, 60)[0]
    e_shstrndx = struct.unpack_from("<H", vmlinux, 62)[0]
    str_off = struct.unpack_from("<Q", vmlinux, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    out = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off = struct.unpack_from("<I", vmlinux, o)[0]
        sh_addr = struct.unpack_from("<Q", vmlinux, o + 16)[0]
        sh_offset = struct.unpack_from("<Q", vmlinux, o + 24)[0]
        sh_size = struct.unpack_from("<Q", vmlinux, o + 32)[0]
        end = vmlinux.find(b"\x00", str_off + name_off)
        name = vmlinux[str_off + name_off : end].decode("ascii", "replace")
        out.append((name, sh_addr, sh_offset, sh_size))
    return out


def ksym_va(vmlinux: bytes, name: str) -> int:
    needle = name.encode() + b"\x00"
    str_off = None
    for sname, addr, off, size in _shdrs(vmlinux):
        if sname != "__ksymtab_strings":
            continue
        rel = vmlinux.find(needle, off, off + size)
        if rel < 0:
            raise SystemExit(f"{name} not in __ksymtab_strings")
        str_off = rel
        str_va = addr + (rel - off)
        break
    else:
        raise SystemExit("no __ksymtab_strings")
    for sname, addr, off, size in _shdrs(vmlinux):
        if sname not in ("__ksymtab", "__ksymtab_gpl"):
            continue
        n = size // 12
        for i in range(n):
            o = off + i * 12
            eva = addr + i * 12
            val_rel, name_rel, _ns = struct.unpack_from("<iii", vmlinux, o)
            name_tgt = (eva + 4 + name_rel) & 0xFFFFFFFFFFFFFFFF
            if name_tgt == str_va:
                return (eva + val_rel) & 0xFFFFFFFFFFFFFFFF
    raise SystemExit(f"no ksymtab entry for {name}")


def _rip_target(vmlinux: bytes, file_off: int, disp_at: int) -> int:
    disp = struct.unpack_from("<i", vmlinux, disp_at)[0]
    insn_end_va = elf_va(vmlinux, disp_at + 4)
    return (insn_end_va + disp) & 0xFFFFFFFFFFFFFFFF


def find_call_after_store(vmlinux: bytes, target_va: int, limit: int = 32) -> int:
    """Return VA of the first call within `limit` bytes after a movq to target_va."""
    start = 0
    while True:
        i = vmlinux.find(b"\x48\x89\x05", start)
        if i < 0:
            break
        if _rip_target(vmlinux, i, i + 3) == target_va:
            window = vmlinux[i : i + limit]
            j = window.find(b"\xe8")
            if j < 0:
                start = i + 1
                continue
            call_off = i + j
            rel = struct.unpack_from("<i", vmlinux, call_off + 1)[0]
            return (elf_va(vmlinux, call_off) + 5 + rel) & 0xFFFFFFFFFFFFFFFF
        start = i + 1
    raise SystemExit(f"no call after store to {target_va:#x}")


def find_skip_and_target(vmlinux: bytes) -> tuple[int, int]:
    """Return (file_offset of xor eax,eax at skip site, file_offset of jmp target)."""
    site = None
    start = 0
    while True:
        i = vmlinux.find(SKIP_SITE, start)
        if i < 0:
            break
        if vmlinux[i + 6 : i + 10] == SKIP_TAIL and vmlinux[i + 14 : i + 21] == XOR_ECX6:
            site = i + 14
            break
        start = i + 1
    if site is None:
        raise SystemExit("IKMF decrypt skip site not found (need 4.0.306+ x64 vmlinuz)")

    s = vmlinux.find(INITRD_IMAGE)
    if s < 0:
        raise SystemExit("/initrd.image string not found")
    str_va = elf_va(vmlinux, s)
    imm = struct.pack("<I", str_va & 0xFFFFFFFF)
    needle = b"\x48\xc7\xc7" + imm
    j = vmlinux.find(needle, site)
    if j < 0:
        raise SystemExit("could not find /initrd.image reference after skip site")
    target = j - 0x28
    if vmlinux[target] != 0x48:
        raise SystemExit(f"unexpected jmp target opcode at {target:#x}")
    return site, target


def i32(n: int) -> bytes:
    n &= 0xFFFFFFFF
    if n >= 0x80000000:
        n -= 0x100000000
    return struct.pack("<i", n)


def assemble_stub(
    cave: int,
    unxz: int,
    k7p9vn: int,
    j4m2zc: int,
    initrd_start: int,
    initrd_end: int,
    kmalloc: int,
    memcpy: int,
) -> bytes:
    code = bytearray()

    def here() -> int:
        return cave + len(code)

    def emit(b: bytes) -> None:
        code.extend(b)

    def emit_rip(opcode: bytes, target: int) -> None:
        emit(opcode)
        emit(i32(target - (here() + 4)))

    def emit_call(target: int) -> None:
        emit(b"\xe8")
        emit(i32(target - (here() + 4)))

    def emit_jmp(target: int) -> None:
        emit(b"\xe9")
        emit(i32(target - (here() + 4)))

    emit(bytes.fromhex("50 51 52 56 57 4150 4151 4152 4153 53"))
    emit_rip(b"\x48\x8b\x35", initrd_start)
    emit(b"\x48\x85\xf6")
    jz1 = len(code)
    emit(b"\x74\x00")
    emit_rip(b"\x48\x8b\x05", initrd_end)
    emit(b"\x48\x29\xf0")
    emit(b"\x48\x3d\x94\x01\x00\x00")
    jbe1 = len(code)
    emit(b"\x76\x00")
    emit(b"\x48\x3d\x00\x00\x00\x08")
    ja1 = len(code)
    emit(b"\x77\x00")
    emit_rip(b"\x48\x89\x05", k7p9vn)
    emit_rip(b"\x48\x8b\x0d", j4m2zc)
    emit(b"\x48\x85\xc9")
    jnz1 = len(code)
    emit(b"\x75\x00")
    emit(b"\x48\x89\xc7")
    emit(b"\x48\x83\xc7\x01")
    emit(b"\x48\x83\xe7\xfc")
    emit(b"\x48\x83\xc7\x02")
    emit_call(kmalloc)
    emit(b"\x48\x85\xc0")
    jz_alloc = len(code)
    emit(b"\x74\x00")
    emit_rip(b"\x48\x89\x05", j4m2zc)
    emit(b"\x48\x89\xc7")
    emit_rip(b"\x48\x8b\x35", initrd_start)
    emit_rip(b"\x48\x8b\x15", k7p9vn)
    emit_call(memcpy)
    emit(b"\xeb\x00")
    jmp_out = len(code) - 2
    fallback = len(code)
    emit_rip(b"\x48\x8b\x35", initrd_start)
    emit_rip(b"\x48\x89\x35", j4m2zc)
    out = len(code)
    code[jz_alloc + 1] = fallback - (jz_alloc + 2)
    code[jmp_out + 1] = out - (jmp_out + 2)
    for pos in (jz1, jbe1, ja1, jnz1):
        rel = out - (pos + 2)
        if not 0 <= rel <= 127:
            raise SystemExit(f"rel8 {rel} at {pos}")
        code[pos + 1] = rel
    emit(bytes.fromhex("5B 415B 415A 4159 4158 5F 5E 5A 59 58"))
    emit_jmp(unxz)
    return bytes(code)


def patch_vmlinuz(src: Path, dst: Path) -> None:
    orig = bytearray(src.read_bytes())
    payload_start, payload_size = find_payload(bytes(orig))
    vmlinux, _xz_actual = xz_decompress(bytes(orig[payload_start:]))
    vmlinux = bytearray(vmlinux)
    site, target = find_skip_and_target(bytes(vmlinux))
    site_va = elf_va(bytes(vmlinux), site)
    unxz_va = elf_va(bytes(vmlinux), target)
    k7 = ksym_va(bytes(vmlinux), "k7p9vn")
    j4 = ksym_va(bytes(vmlinux), "j4m2zc")
    initrd_end = k7 - 16
    initrd_start = k7 - 8
    kmalloc = find_call_after_store(bytes(vmlinux), k7, 32)
    memcpy = find_call_after_store(bytes(vmlinux), j4, 48)
    cave_va = site_va + 16
    cave_off = elf_file_of(bytes(vmlinux), cave_va)
    if cave_off is None:
        raise SystemExit(f"cave {cave_va:#x} not in PT_LOAD")
    stub = assemble_stub(cave_va, unxz_va, k7, j4, initrd_start, initrd_end, kmalloc, memcpy)
    if cave_va + len(stub) > unxz_va:
        raise SystemExit(f"stub {len(stub)} overlaps unxz")
    vmlinux[cave_off : cave_off + len(stub)] = stub
    rel = cave_va - (site_va + 5)
    vmlinux[site : site + 5] = bytes([0xE9]) + struct.pack("<i", rel)
    print(
        f"[xzskip] jmp {site_va:#x} -> cave {cave_va:#x} -> unxz {unxz_va:#x} "
        f"k7={k7:#x} j4={j4:#x} kmalloc={kmalloc:#x} memcpy={memcpy:#x} stub={len(stub)}"
    )

    params = parse_xz_params(bytes(orig), payload_start)
    new_xz = xz_compress(bytes(vmlinux), check=params["check"], filters=params["filters"])
    if len(new_xz) > payload_size:
        filters = []
        for f in params["filters"]:
            if f.get("id") == 33:
                f = dict(f)
                f["lc"] = 4
            filters.append(f)
        new_xz = xz_compress(bytes(vmlinux), check=params["check"], filters=filters)
        print(f"[xzskip] retried xz lc=4 size={len(new_xz)}")
    if len(new_xz) > payload_size:
        raise SystemExit(
            f"compressed payload {len(new_xz)} > original {payload_size}; "
            "refusing to grow bzImage"
        )
    prefix = bytes(orig[:payload_start])
    gap = b"\x00" * (payload_size - len(new_xz))
    suffix = bytes(orig[payload_start + payload_size :])
    out = prefix + new_xz + gap + suffix
    if len(out) != len(orig):
        raise SystemExit(f"size changed {len(orig)} -> {len(out)}")
    dst.write_bytes(out)
    print(f"[xzskip] wrote {dst} ({len(out)} bytes)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input_vmlinuz")
    ap.add_argument("output_vmlinuz")
    args = ap.parse_args()
    patch_vmlinuz(Path(args.input_vmlinuz), Path(args.output_vmlinuz))


if __name__ == "__main__":
    main()
