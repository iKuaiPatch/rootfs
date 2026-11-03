#!/usr/bin/env python3
"""Unpack 4.0.306+ encrypted initrd by letting the official kernel decrypt it.

Boots vmlinuz+rootfs in QEMU, stops at the unxz() call, and writes the
plaintext xz from guest memory. Requires root, KVM, qemu-system-x86_64.
"""
from __future__ import annotations

import argparse
import lzma
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from patch_vmlinuz import find_payload, xz_decompress  # noqa: E402

UNXZ_CALL_PREFIX = bytes.fromhex("4889c74829f2e8")
DIRECT_MAP = 0xFFFF888000000000


def log(msg: str) -> None:
    print(f"[qemu-unpack] {msg}", flush=True)


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
    raise SystemExit(f"no ELF mapping for file offset {file_off:#x}")


def find_unxz_call(vmlinux: bytes) -> int:
    i = vmlinux.find(UNXZ_CALL_PREFIX)
    if i < 0 or vmlinux.find(UNXZ_CALL_PREFIX, i + 1) >= 0:
        raise SystemExit(
            "could not uniquely locate unxz() call in vmlinux "
            "(only 4.0.306+ x64 kernels with the IKMF decrypt path are supported)"
        )
    return elf_va(vmlinux, i + 6)


def vmlinux_from_bzimage(vmlinuz: Path) -> bytes:
    data = vmlinuz.read_bytes()
    start, _ = find_payload(data)
    vmlinux, _ = xz_decompress(data[start:])
    return vmlinux


class Rsp:
    def __init__(self, host: str, port: int) -> None:
        t0 = time.time()
        last: OSError | None = None
        while time.time() - t0 < 15:
            try:
                self.s = socket.create_connection((host, port), timeout=5)
                break
            except OSError as e:
                last = e
                time.sleep(0.1)
        else:
            raise SystemExit(f"gdbstub connect failed: {last}")
        self.s.settimeout(90)

    @staticmethod
    def _csum(data: bytes) -> str:
        return f"{sum(data) % 256:02x}"

    def send(self, payload: str) -> str:
        raw = payload.encode()
        self.s.sendall(b"$" + raw + b"#" + self._csum(raw).encode())
        return self._read()

    def _read(self) -> str:
        buf = b""
        while True:
            b = self.s.recv(1)
            if not b:
                raise RuntimeError("gdbstub eof")
            if b == b"+":
                continue
            if b == b"$":
                buf = b""
                continue
            if b == b"#":
                self.s.recv(2)
                self.s.sendall(b"+")
                return buf.decode("latin1")
            buf += b

    def cont(self) -> str:
        raw = b"c"
        self.s.sendall(b"$" + raw + b"#" + self._csum(raw).encode())
        return self._read()


def u64(g: str, idx: int) -> int:
    return int.from_bytes(bytes.fromhex(g[idx * 16 : (idx + 1) * 16]), "little")


def qemu_ram_hva(pid: int, gpa: int) -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        rng, perm, *_ = line.split()
        if not perm.startswith("rw"):
            continue
        a, b = rng.split("-")
        start, end = int(a, 16), int(b, 16)
        if end - start >= 512 * 1024 * 1024:
            return start + gpa
    raise SystemExit("could not find QEMU guest RAM mapping")


def is_ikmf(blob: bytes, initrd_length: int | None = None) -> bool:
    n = initrd_length if initrd_length else len(blob)
    if n > len(blob):
        n = len(blob)
    if n < 0x294:
        return False
    return blob[n - 0x294 + 20 : n - 0x294 + 24] == b"IKMF"


def unpack(
    vmlinuz: Path,
    initrd: Path,
    output_xz: Path,
    initrd_length: int | None = None,
    memory_mib: int = 2048,
    gdb_port: int = 0,
) -> None:
    if os.geteuid() != 0:
        raise SystemExit("qemu unpack must run as root")
    if not Path("/dev/kvm").exists():
        raise SystemExit("/dev/kvm is required")
    qemu = subprocess.check_output(["which", "qemu-system-x86_64"], text=True).strip()

    vmlinux = vmlinux_from_bzimage(vmlinuz)
    unxz_va = find_unxz_call(vmlinux)
    log(f"unxz call at {unxz_va:#x}")

    length = initrd_length or initrd.stat().st_size
    if gdb_port <= 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            gdb_port = s.getsockname()[1]

    work = output_xz.parent / f".qemu-unpack-{os.getpid()}"
    work.mkdir(parents=True, exist_ok=True)
    pidfile = work / "qemu.pid"
    serial = work / "serial.log"
    append = (
        "BOOT_IMAGE=/boot/vmlinuz root=/dev/ram0 rootfstype=ext4 rootwait "
        f"retain_initrd console=ttyS0,115200n8 bootguide=hd initrd_length={length}"
    )
    cmd = [
        qemu,
        "-enable-kvm",
        "-cpu",
        "host",
        "-m",
        str(memory_mib),
        "-smp",
        "1",
        "-name",
        "ikuai-unpack",
        "-display",
        "none",
        f"-serial",
        f"file:{serial}",
        "-kernel",
        str(vmlinuz),
        "-initrd",
        str(initrd),
        "-append",
        append,
        "-gdb",
        f"tcp:127.0.0.1:{gdb_port}",
        "-S",
        "-pidfile",
        str(pidfile),
        "-daemonize",
    ]
    log("starting qemu")
    subprocess.run(cmd, check=True)
    pid = int(pidfile.read_text().strip())
    if Path(f"/proc/{pid}/comm").read_text().strip()[:4] != "qemu":
        raise SystemExit(f"pidfile {pid} is not qemu")

    try:
        r = Rsp("127.0.0.1", gdb_port)
        r.send("?")
        bp = r.send(f"Z1,{unxz_va:x},1")
        if bp != "OK":
            raise SystemExit(f"hardware breakpoint rejected: {bp}")
        stop = r.cont()
        log(f"stopped {stop[:40]}")
        g = r.send("g")
        rip = u64(g, 16)
        rsi = u64(g, 4)
        rdx = u64(g, 3)
        if rip != unxz_va:
            raise SystemExit(f"stopped at {rip:#x}, expected {unxz_va:#x}")
        if rdx < 16 or rdx > 200 * 1024 * 1024:
            raise SystemExit(f"implausible xz size {rdx}")
        gpa = rsi - DIRECT_MAP
        hva = qemu_ram_hva(pid, gpa)
        log(f"dumping {rdx} bytes gpa={gpa:#x}")
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
            mem.seek(hva)
            blob = mem.read(rdx)
        if blob[:6] != b"\xfd7zXZ\x00":
            raise SystemExit(f"guest buffer is not xz (head={blob[:8].hex()})")
        try:
            dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            plain = dec.decompress(blob)
            used = len(blob) - len(dec.unused_data)
            blob = blob[:used]
        except lzma.LZMAError as e:
            raise SystemExit(f"dumped buffer is not a valid xz stream: {e}") from e
        if plain[0x438:0x43A] != b"\x53\xef":
            raise SystemExit("decompressed payload is not ext2")
        output_xz.parent.mkdir(parents=True, exist_ok=True)
        output_xz.write_bytes(blob)
        log(f"wrote {output_xz} ({len(blob)} bytes, ext2 {len(plain)})")
        r.send(f"z1,{unxz_va:x},1")
        r.send("D")
        r.s.close()
    finally:
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(30):
                if not Path(f"/proc/{pid}").exists():
                    break
                time.sleep(0.1)
            else:
                os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        for p in (pidfile, serial):
            p.unlink(missing_ok=True)
        try:
            work.rmdir()
        except OSError:
            pass


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("vmlinuz")
    ap.add_argument("initrd")
    ap.add_argument("output_xz")
    ap.add_argument("-l", "--length", type=int, default=0)
    ap.add_argument("-m", "--memory", type=int, default=2048)
    ap.add_argument("--gdb-port", type=int, default=0)
    args = ap.parse_args()
    unpack(
        Path(args.vmlinuz),
        Path(args.initrd),
        Path(args.output_xz),
        initrd_length=args.length or None,
        memory_mib=args.memory,
        gdb_port=args.gdb_port,
    )


if __name__ == "__main__":
    main()
