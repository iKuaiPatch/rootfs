# iKuai rootfs tools

[![License: WTFPL](https://img.shields.io/badge/License-WTFPL-brightgreen.svg)](./LICENSE)
[![CoC:WTFCoC](https://img.shields.io/badge/CoC-WTFCoC-brightgreen.svg)](./CODE_OF_CONDUCT.md)

ETH(USDT): 0x4568da7585f7d7d980fa30fcd6dd6e151778bbef

TRX(USDT): THYrLLaMpb7zp5ZZXq72XGsgvLqnbdk821

## Usage

```
Usage: ./build.sh <command> [args...]

Commands:
  unpack <xxx.iso|xxx.bin> [-v1|-v2|-v3|-ikmf] [-u PUBLIC_KEY]
      unpack iso or bin file
      -u PUBLIC_KEY  Override RSA public key for v3 signature verification
      -ikmf          4.0.306+ x64: boot official kernel in QEMU and dump plaintext xz
                     IKMF images also auto-select this path without -ikmf
                     -qemu and -xzskip are aliases of -ikmf

  patch_kernel -u OLD_PUBLIC_KEY -n NEW_PUBLIC_KEY [-i INPUT_VMLINUZ] [-o OUTPUT_VMLINUZ]
      patch embedded RSA public key in vmlinuz
      default input/output is rootfs-unpack/vmlinuz

  pack_rootfs [firmware_id] [version] [build_time]
      pack rootfs

  pack_bin [firmware_id] [version] [build_time] [-v1|-v2|-v3|-ikmf] [-p PRIVATE_KEY]
      pack bin file
      -v3 -p PRIVATE_KEY  Use v3 format with specified RSA private key for signing
      -ikmf               plaintext xz + 0x194 IKMF MD5 trailer + kernel that
                          skips IKMF decrypt and fills j4m2zc/k7p9vn
                          auto-selected after an IKMF unpack
                          -qemu and -xzskip are aliases of -ikmf

  pack_iso [firmware_id] [version] [build_time] [-v1|-v2|-v3|-ikmf] [-p PRIVATE_KEY]
      pack iso file
      -v3 -p PRIVATE_KEY  Use v3 format with specified RSA private key for signing
      -ikmf               same as pack_bin -ikmf

  patch <xxx.bin|xxx.iso> <out_type:bin|iso> <patch_dir> [firmware_id] [version] [build_time] [-v1|-v2|-v3|-ikmf] [-u OLD_PUBLIC_KEY] [-n NEW_PUBLIC_KEY] [-p PRIVATE_KEY]
      patch iso or bin file
      -u OLD_PUBLIC_KEY  Override RSA public key for v3 unpack verification and vmlinuz patch source key
      -n NEW_PUBLIC_KEY  Automatically patch vmlinuz to the replacement RSA public key
      -p PRIVATE_KEY     RSA private key for v3 re-encrypt signing

  clean
      clean work dir

Args:
  Build time:
      Empty : Not change
      0     : Current time
      Number: Use input time

  Firmware id:
      Empty: Not change
      10001: Free Edition
      10002: Enterprise
      Other: Use input id

  Version:
      Empty: Not change
      Other: Use input version

Examples:
  ./build.sh unpack xxx.iso
  ./build.sh unpack xxx.iso -v2
  ./build.sh unpack xxx.iso -v3
  ./build.sh unpack xxx.iso -v3 -u public.pem
  ./build.sh unpack xxx.iso -ikmf
  ./build.sh patch_kernel -u old_public.pem -n new_public.pem
  ./build.sh patch_kernel -i rootfs-unpack/vmlinuz -o work/vmlinuz.patched -u old_public.pem -n new_public.pem
  ./build.sh unpack xxx.bin
  ./build.sh pack_rootfs
  ./build.sh pack_bin Id Version 0
  ./build.sh pack_bin Id Version 0 -v3 -p private.pem
  ./build.sh pack_bin Id Version 0 -ikmf
  ./build.sh pack_iso
  ./build.sh pack_iso "" "" "" -v3 -p private.pem
  ./build.sh patch xxx.iso iso patch_dir
  ./build.sh patch xxx.iso iso patch_dir "" "" "" -v3 -u old_public.pem -n new_public.pem -p private.pem
  ./build.sh patch xxx.bin bin patch_dir "" "" 202509221910
```

4.0.306+ x64 (`IKMF` trailer) cannot be decrypted by `-v3`. Unpack boots the official kernel in QEMU and copies the plaintext xz at `unxz()` (needs root, KVM, `qemu-system-x86_64`). After unpack, `pack_bin` / `pack_iso` without extra flags emit a plaintext xz initrd, a 0x194 IKMF MD5 trailer, and a kernel that skips IKMF decrypt then copies the ramdisk into `j4m2zc`/`k7p9vn` so stock `ik_core.ko` accepts it. The flag for that path is `-ikmf`. Details: [tools/ikmf.md](tools/ikmf.md).
