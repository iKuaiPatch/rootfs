#!/bin/bash

if [ "$(whoami)" != 'root' ]; then
    echo 'please run as root'
    exit 1
fi

work_dir="$(pwd)/work"
unpack_dir="$(pwd)/rootfs-unpack"

bin_files="$(pwd)/bin-boot-files"
iso_files="$(pwd)/iso-boot-files"
tools_dir="$(pwd)/tools"

. "$tools_dir/utils.sh"
. "$tools_dir/build_tools.sh"

# -ikmf is the 4.0.306+ path (QEMU unpack, plaintext xz pack).
# -qemu and -xzskip are aliases of -ikmf.
function normalize_rootfs_flag () {
    case "$1" in
        -ikmf|-qemu|-xzskip) printf '%s\n' -ikmf ;;
        *) printf '%s\n' "$1" ;;
    esac
}

function unpack_iso () {
    local file=$1
    local decode_flag="$2"
    local public_key_file="$3"

    log INFO "Mount iso ..."
    mkdir $work_dir/iso
    mount $file $work_dir/iso
    if [ $? -ne 0 ]; then
        log ERROR "Mount iso fail!"
        exit 1
    fi

    local GRUB_CFG="$work_dir/iso/boot/grub/grub.cfg"

    local ikversion=$(grep -E "^set ikversion=" "$GRUB_CFG" | head -n1 | sed 's/set ikversion=//')
    local initrd_length=$(grep -E "^set initrd_length=" "$GRUB_CFG" | head -n1 | sed 's/set initrd_length=//')

    if [[ $ikversion = "" || $initrd_length = "" ]]; then
        log ERROR "Get iKuai version and initrd lenght fail!"
        exit 1
    fi

    log INFO "iKuai version: $ikversion"
    log INFO "iKuai initrf lenght: $initrd_length"

    log INFO "Copy rootfs and vmlinuz ..."
    cp $work_dir/iso/boot/rootfs $work_dir/rootfs
    cp $work_dir/iso/boot/vmlinuz $unpack_dir/vmlinuz

    if [ ! -f "$work_dir/rootfs" ]; then
        log ERROR "Copy rootfs fail!"
        exit 1
    fi
    if [ ! -f "$unpack_dir/vmlinuz" ]; then
        log ERROR "Copy vmlinuz fail!"
        exit 1
    fi

    log INFO "Umount iso ..."
    umount_retry $work_dir/iso
    if [ $? -ne 0 ]; then
        log ERROR "Umount iso fail!"
        exit 1
    fi

    unpack_rootfs "$work_dir/rootfs" "$initrd_length" "$decode_flag" "$public_key_file"
}

function unpack_bin () {
    # ┌─────────────────┬──────────────────────┬─────────────────────┐
    # │  Header Length  │    Header Data       │   Compressed Data   │
    # │    (4 bytes)    │   (headlen bytes)    │   (remaining data)  │
    # │   Big Endian    │                      │                     │
    # └─────────────────┴──────────────────────┴─────────────────────┘
    #      0-3 bytes        4 to (4+headlen)      (4+headlen) to EOF

    local file="$1"
    local decode_flag="$2"
    local public_key_file="$3"

    log INFO "Export bin header ..."
    headlen=$(printf "%u" 0x$(hexdump -v -n 4 $file -e '4/1 "%02x"'))
    printf "\x1f\x8b\x08\x00\x6f\x9b\x4b\x59\x02\x03" > $work_dir/header.bin
    dd if=$file bs=1 skip=4 count=$headlen >> $work_dir/header.bin
    gunzip < $work_dir/header.bin > $unpack_dir/header_info.json

    log INFO "Export firmware iso ..."
    dd if=$file bs=$((headlen+4)) skip=1 >> $work_dir/firmware.iso.gz
    gzip -d < $work_dir/firmware.iso.gz > $work_dir/firmware.iso
    if [ $? -ne 0 ]; then
        log ERROR "Decompress firmware iso fail!"
        exit 1
    fi

    log INFO "Mount iso ..."
    mkdir $work_dir/iso
    mount $work_dir/firmware.iso $work_dir/iso
    if [ $? -ne 0 ]; then
        log ERROR "Mount iso fail!"
        exit 1
    fi

    log INFO "Copy rootfs and vmlinuz ..."
    cp $work_dir/iso/boot/rootfs $work_dir/rootfs
    cp $work_dir/iso/boot/vmlinuz $unpack_dir/vmlinuz

    if [ ! -f "$work_dir/rootfs" ]; then
        log ERROR "Copy rootfs fail!"
        exit 1
    fi
    if [ ! -f "$unpack_dir/vmlinuz" ]; then
        log ERROR "Copy vmlinuz fail!"
        exit 1
    fi

    log INFO "Umount iso ..."
    umount_retry $work_dir/iso
    if [ $? -ne 0 ]; then
        log ERROR "Umount iso fail!"
        exit 1
    fi

    unpack_rootfs "$work_dir/rootfs" "" "$decode_flag" "$public_key_file"
}

function unpack_rootfs () {
    local file="$1"
    local initrd_length="$2"
    local decode_flag="$3"
    local public_key_file="$4"
    local decode_file="$file"

    if [ "$decode_flag" = "" ]; then
        decode_flag="-v1"
    fi
    decode_flag="$(normalize_rootfs_flag "$decode_flag")"

    if [ "$decode_flag" != "-v1" ] && [ "$decode_flag" != "-v2" ] && [ "$decode_flag" != "-v3" ] && [ "$decode_flag" != "-ikmf" ]; then
        log ERROR "Unknown rootfs decode version: $decode_flag"
        exit 1
    fi

    if [ "$initrd_length" != "" ]; then
        initrd_length="-l $initrd_length"
    fi

    mkdir $work_dir/rootfs_decrypt

    local pub_key_opt=""
    if [ "$public_key_file" != "" ]; then
        pub_key_opt="-u $public_key_file"
    fi

    local use_qemu=0
    if [ "$decode_flag" = "-ikmf" ]; then
        use_qemu=1
    else
        if python3 - "$decode_file" "${2}" <<'PY'
import sys
from pathlib import Path
blob = Path(sys.argv[1]).read_bytes()
n = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else len(blob)
if n > len(blob):
    n = len(blob)
sys.exit(0 if n >= 0x294 and blob[n - 0x294 + 20:n - 0x294 + 24] == b"IKMF" else 1)
PY
        then
            log INFO "IKMF trailer detected, using QEMU unpack"
            use_qemu=1
        fi
    fi

    if [ "$use_qemu" = "1" ]; then
        local qemu_len=()
        if [ "$2" != "" ]; then
            qemu_len=(-l "$2")
        fi
        log INFO "Decrypt rootfs via QEMU (official kernel) ..."
        python3 "$tools_dir/qemu_unpack_initrd.py" \
            "$unpack_dir/vmlinuz" "$decode_file" \
            "$work_dir/rootfs_decrypt/rootfs.ext2" \
            "${qemu_len[@]}"
        if [ $? -ne 0 ]; then
            log ERROR "QEMU decrypt rootfs fail!"
            exit 1
        fi
        touch "$unpack_dir/.ikmf"
    else
        ensure_rootfs_tool

        log INFO "Decrypt rootfs ..."
        "$tools_dir/rootfs" decrypt "$decode_file" "$work_dir/rootfs_decrypt" $decode_flag $initrd_length $pub_key_opt
        if [ $? -ne 0 ]; then
            log ERROR "Decrypt rootfs fail!"
            exit 1
        fi
    fi

    if [ -f "$work_dir/rootfs_decrypt/end.gz" ]; then
        log INFO "Copy grub.gz ..."
        cp $work_dir/rootfs_decrypt/end.gz $unpack_dir/grub.gz
    fi

    log INFO "Decompress rootfs ..."
    xz -dkc $work_dir/rootfs_decrypt/rootfs.ext2 > $work_dir/rootfs.ext2
    if [ $? -ne 0 ]; then
        log ERROR "Decompress rootfs fail!"
        exit 1
    fi
    
    log INFO "Mount rootfs ..."
    mkdir $work_dir/rootfs-mount
    mount $work_dir/rootfs.ext2 $work_dir/rootfs-mount
    if [ $? -ne 0 ]; then
        log ERROR "Mount rootfs fail!"
        exit 1
    fi

    log INFO "Copy rootfs to $unpack_dir/rootfs ..."
    mkdir $unpack_dir/rootfs
    cp -rfp $work_dir/rootfs-mount/* $unpack_dir/rootfs
    if [ $? -ne 0 ]; then
        log ERROR "Copy rootfs to $unpack_dir/rootfs fail!"
        exit 1
    fi

    log INFO "Umount iso ..."
    umount_retry $work_dir/rootfs-mount
    if [ $? -ne 0 ]; then
        log ERROR "Umount rootfs fail!"
        exit 1
    fi
}

function unpack () {
    local file="$1"
    local decode_flag="-v1"
    local public_key_file=""

    # Parse options from all arguments
    local args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do
        case "${args[i]}" in
            -v1|-v2|-v3|-ikmf|-qemu|-xzskip) decode_flag="${args[i]}" ;;
            -u) i=$((i+1)); public_key_file="${args[i]}" ;;
        esac
    done

    if [ ! -f "$file" ]; then
        log ERROR "File not exist."
        exit 1
    fi
    
    clean_all
    mkdir $work_dir
    mkdir $unpack_dir

    echo "Process $file file...."
    ext="${file##*.}"
    if [ "$ext" = "iso" ]; then
        unpack_iso $file "$decode_flag" "$public_key_file"
    elif [ "$ext" = "bin" ]; then
        unpack_bin $file "$decode_flag" "$public_key_file"
    else
        log ERROR "Unknown file."
        exit 1
    fi

    clean_work

    log INFO "Unpack $file success!"
}

function update_release_conf () {
    log INFO "Start update release file ..."
    local release_file="$unpack_dir/rootfs/etc/release"

    if [ ! -f "$release_file" ]; then
        log ERROR "rootfs release file not found!"
        exit 1
    fi

    firmware_id="$1"
    version="$2"
    build_time="$3"
    
    if [ "$firmware_id" = "" ]; then
        firmware_id=$(get_conf FIRMWAREID "$release_file")
    fi
    if [ "$version" = "" ]; then
        version=$(get_conf VERSION "$release_file")
    fi
    if [ "$build_time" = "0" ]; then
        build_time=$(date +"%Y%m%d%H%M")
    elif [ "$build_time" = "" ]; then
        build_time=$(get_conf BUILD_DATE "$release_file")
    fi

    sysbit=$(get_conf SYSBIT "$release_file")
    is_enterprise=$(get_conf ENTERPRISE "$release_file")

    local major=$(echo $version | cut -d. -f1)
    local minor=$(echo $version | cut -d. -f2)
    local patch=$(echo $version | cut -d. -f3)
    local version_num=$(printf "%d%04d%04d" "$major" "$minor" "$patch")

    if [ "$is_enterprise" != "" ]; then
        is_enterprise=" $is_enterprise"
    fi

    version_str="$version $sysbit$is_enterprise Build$build_time"

    set_conf FIRMWAREID  "$firmware_id" "$release_file" none
    set_conf VERSION     "$version"     "$release_file" none
    set_conf VERSION_NUM "$version_num" "$release_file" none
    set_conf BUILD_DATE  "$build_time"  "$release_file" none
    set_conf VERSTRING   "$version_str" "$release_file" always
}

function build_iso_rootfs_grub () {
    local output_file="$1"
    local tail_dir="$work_dir/rootfs-tail-grub"
    local root_grub="$tail_dir/root.grub"
    local grub_cfg="$root_grub/boot/grub/grub.cfg"
    local grub_disk_cfg="$root_grub/boot/grub/grub-disk.cfg"

    if [ "$version" = "" ]; then
        log ERROR "Version is empty, cannot build rootfs grub tail."
        exit 1
    fi

    if [ ! -d "$iso_files/iso" ]; then
        log ERROR "Not found iso boot files: $iso_files/iso"
        exit 1
    fi

    if [ ! -f "$unpack_dir/vmlinuz" ]; then
        log ERROR "Not found vmlinuz: $unpack_dir/vmlinuz"
        exit 1
    fi

    rm -rf "$tail_dir"
    mkdir -p "$root_grub"

    log INFO "Build rootfs tail grub files"
    cp -rfp "$iso_files/iso/." "$root_grub"
    if [ $? -ne 0 ]; then
        log ERROR "Copy iso boot files fail!"
        exit 1
    fi

    rm -f "$root_grub/boot.catalog" "$root_grub/boot/rootfs"
    cp -fp "$unpack_dir/vmlinuz" "$root_grub/boot/vmlinuz"
    if [ $? -ne 0 ]; then
        log ERROR "Copy vmlinuz to rootfs tail grub fail!"
        exit 1
    fi

    if [ ! -f "$grub_cfg" ] || [ ! -f "$grub_disk_cfg" ]; then
        log ERROR "Not found grub cfg in rootfs tail grub."
        exit 1
    fi

    sed -i "s|%version%|$version|g" "$grub_cfg" "$grub_disk_cfg"
    sed -i "s|^set ikversion=.*|set ikversion=$version|g" "$grub_cfg" "$grub_disk_cfg"
    sed -i 's|set initrd_length=%initrd_length%|set initrd_length=""|g' "$grub_cfg"
    sed -i 's|initrd_length=%initrd_length%|initrd_length=$3|g' "$grub_cfg"
    if [ $? -ne 0 ]; then
        log ERROR "Update rootfs tail grub cfg fail!"
        exit 1
    fi

    if grep -R -E "%version%|%initrd_length%" "$grub_cfg" "$grub_disk_cfg" >/dev/null; then
        log ERROR "Rootfs tail grub cfg still contains template placeholders."
        exit 1
    fi

    log INFO "Compress rootfs tail grub"
    tar -czf "$output_file" -C "$tail_dir" root.grub
    if [ $? -ne 0 ]; then
        log ERROR "Compress rootfs tail grub fail!"
        exit 1
    fi
}

function pack_rootfs () {
    if [ ! -d "$unpack_dir" ]; then
        log ERROR "Not found unpack rootfs!"
        exit 1
    fi

    clean_work

    update_release_conf "$1" "$2" "$3"
    if [ $? -ne 0 ]; then
        log ERROR "Update release file fail!"
        exit 1
    fi

    mkdir $work_dir

    local grub_file="$4"
    local grub=""
    local append_size=0
    local encrypt_flag="${5:--v2}"
    local private_key_file="$6"

    encrypt_flag="$(normalize_rootfs_flag "$encrypt_flag")"
    if [ "$encrypt_flag" = "-v2" ] && [ -f "$unpack_dir/.ikmf" ]; then
        log INFO "IKMF unpack marker present, packing with -ikmf"
        encrypt_flag="-ikmf"
    fi

    if [ "$grub_file" = "__auto_iso_grub__" ]; then
        grub_file="$work_dir/grub.gz"
        build_iso_rootfs_grub "$grub_file"
    fi

    if [ "$grub_file" != "" ]; then
        if [ -f "$grub_file" ]; then
            log INFO "Append file $grub_file"
            grub="-a $grub_file"
            append_size=$(wc -c < "$grub_file")
        else
            log ERROR "Not found grub.gz"
            exit 1
        fi
    fi

    local priv_key_opt=""
    if [ "$private_key_file" != "" ]; then
        priv_key_opt="-p $private_key_file"
    fi

    log INFO "Create rootfs.img size 512M"
    dd if=/dev/zero of=$work_dir/rootfs.img bs=512M count=1
    if [ $? -ne 0 ]; then
        log ERROR "Create rootfs.img fail!"
        exit 1
    fi

    log INFO "Create ext4 filesystem"
    mkfs.ext4 -F -L linuxroot $work_dir/rootfs.img
    if [ $? -ne 0 ]; then
        log ERROR "Create ext4 filesystem fail!"
        exit 1
    fi

    log INFO "Mount rootfs"
    mkdir $work_dir/rootfs-mount
    mount $work_dir/rootfs.img $work_dir/rootfs-mount
    if [ $? -ne 0 ]; then
        log ERROR "Mount rootfs fail!"
        exit 1
    fi

    log INFO "Copy system file"
    cp -rfp $unpack_dir/rootfs/* $work_dir/rootfs-mount
    if [ $? -ne 0 ]; then
        log ERROR "Copy system file fail!"
        exit 1
    fi

    log INFO "Umount rootfs"
    umount_retry $work_dir/rootfs-mount
    if [ $? -ne 0 ]; then
        log ERROR "Umount rootfs fail!"
        exit 1
    fi

    log INFO "Check and resize rootfs"
    e2fsck -p -f $work_dir/rootfs.img
    if [ $? -ne 0 ]; then
        log ERROR "Check rootfs fail!"
        exit 1
    fi

    resize2fs -M $work_dir/rootfs.img
    if [ $? -ne 0 ]; then
        log ERROR "Resize rootfs fail!"
        exit 1
    fi

    log INFO "Compression rootfs"
    xz -zkc -T0 --check=crc32 $work_dir/rootfs.img > $work_dir/rootfs.img.xz
    if [ $? -ne 0 ]; then
        log ERROR "Compression rootfs fail!"
        exit 1
    fi

    if [ "$encrypt_flag" = "-ikmf" ]; then
        log INFO "Patch vmlinuz to skip IKMF when initrd is already xz"
        python3 "$tools_dir/patch_vmlinuz_xzskip.py" \
            "$unpack_dir/vmlinuz" "$work_dir/vmlinuz.xzskip"
        if [ $? -ne 0 ]; then
            log ERROR "Patch vmlinuz xz-skip fail!"
            exit 1
        fi
        mv "$work_dir/vmlinuz.xzskip" "$unpack_dir/vmlinuz"
        log INFO "Append 0x194 IKMF MD5 trailer for official ik_core"
        python3 "$tools_dir/ikmf_sign_initrd.py" \
            "$work_dir/rootfs.img.xz" "$work_dir/rootfs.img.xz.ikmf"
        if [ $? -ne 0 ]; then
            log ERROR "IKMF sign initrd fail!"
            exit 1
        fi
        cp "$work_dir/rootfs.img.xz.ikmf" "$work_dir/rootfs.img.xz.bin"
        if [ "$grub" != "" ]; then
            cat "$grub_file" >> "$work_dir/rootfs.img.xz.bin"
        fi
    else
        ensure_rootfs_tool

        log INFO "Encrypt rootfs"
        "$tools_dir/rootfs" encrypt "$work_dir/rootfs.img.xz" "$work_dir/rootfs.img.xz.bin" $encrypt_flag $grub $priv_key_opt
        if [ $? -ne 0 ]; then
            log ERROR "Encrypt rootfs fail!"
            exit 1
        fi
    fi
    firmware_size=$(wc -c < "$work_dir/rootfs.img.xz.bin")
    initrd_length=$firmware_size
    if [ "$append_size" -gt 0 ]; then
        initrd_length=$((firmware_size - append_size))
    fi

    log INFO "Pack rootfs success."
    log INFO "File path: $work_dir/rootfs.img.xz.bin"
    log INFO "Initrd length: $initrd_length"
}

function pack_bin () {
    if [ ! -d "$unpack_dir" ]; then
        log ERROR "Not found unpack rootfs!"
        exit 1
    fi

    local firmware_id="$1"
    local version_arg="$2"
    local build_time="$3"
    local encrypt_flag="-v2"
    local private_key_file=""

    # Parse optional flags
    local i=4
    while [ $i -le $# ]; do
        arg="${!i}"
        case "$arg" in
            -v1|-v2|-v3|-ikmf|-qemu|-xzskip) encrypt_flag="$arg" ;;
            -p) i=$((i+1)); private_key_file="${!i}" ;;
        esac
        i=$((i+1))
    done

    pack_rootfs "$firmware_id" "$version_arg" "$build_time" "" "$encrypt_flag" "$private_key_file"
    if [ $? -ne 0 ]; then
        log ERROR "Update release file fail!"
        exit 1
    fi

    log INFO "Create iso"
    dd if=/dev/zero of=$work_dir/firmware.iso bs=1024 count=51200
    mkfs.ext2 -L -F $work_dir/firmware.iso
    if [ $? -ne 0 ]; then
        log ERROR "Create iso fail!"
        exit 1
    fi

    log INFO "Mount iso"
    mkdir $work_dir/iso
    mount $work_dir/firmware.iso $work_dir/iso
    if [ $? -ne 0 ]; then
        log ERROR "Mount iso fail!"
        exit 1
    fi

    log INFO "Copy iso file"
    cp -rfp $bin_files/* $work_dir/iso
    cp $unpack_dir/vmlinuz $work_dir/iso/boot/vmlinuz
    cp $work_dir/rootfs.img.xz.bin $work_dir/iso/boot/rootfs
    if [ $? -ne 0 ]; then
        log ERROR "Copy iso file fail!"
        exit 1
    fi

    log INFO "Update grub cfg"
    sed -i "s|%version%|$version|g" $work_dir/iso/boot/grub/grub.cfg
    if [ $? -ne 0 ]; then
        log ERROR "Update grub cfg fail!"
        exit 1
    fi

    log INFO "Umount iso"
    umount_retry $work_dir/iso
    if [ $? -ne 0 ]; then
        log ERROR "Umount iso fail!"
        exit 1
    fi

    log INFO "Compressed iso"
    gzip -n -c $work_dir/firmware.iso > $work_dir/firmware.iso.gz
    if [ $? -ne 0 ]; then
        log ERROR "Compressed iso fail!"
        exit 1
    fi

    # ┌─────────────────┬──────────────────────┬─────────────────────┐
    # │  Header Length  │    Header Data       │   Compressed Data   │
    # │    (4 bytes)    │   (headlen bytes)    │   (remaining data)  │
    # │   Big Endian    │                      │                     │
    # └─────────────────┴──────────────────────┴─────────────────────┘
    #      0-3 bytes            headlen                 to EOF

    log INFO "Build version json"
    local size=$(wc -c $work_dir/firmware.iso.gz | cut -d' ' -f1)
    local md5=$(md5sum $work_dir/firmware.iso.gz)
    local sha256=$(sha256sum $work_dir/firmware.iso.gz)

    is_enterprise=$(echo "$is_enterprise" | tr ' ' '_')
    local name="iKuai8_${sysbit}_${version}${is_enterprise}_Build${build_time}.bin"
    
    local formatted=$(echo "$build_time" | sed 's/\(....\)\(..\)\(..\)\(..\)\(..\)/\1-\2-\3 \4:\5:00/')
    local timestamp=$(date -d "$formatted" +%s)

    local json='{filename:$filename,firmwareid:$firmwareid,version:$version,sysbit:$sysbit,timestamp:$timestamp,length:$length,md5:$md5,sha256:$sha256}'
    local result=$(
        jq -c -n \
            --arg filename "$name" \
            --arg firmwareid "$firmware_id" \
            --arg version "$version" \
            --arg sysbit "$sysbit" \
            --arg timestamp "$timestamp" \
            --arg length "$size" \
            --arg md5 "${md5:0:32}" \
            --arg sha256 "${sha256:0:32}" \
            "$json"
    )
    if [ "$result" = "" ]; then
        log ERROR "Generate version json fail!"
        exit 1
    fi

    log INFO "Compressed version json"
    echo "$result" > $work_dir/header_info.json
    gzip -n -c $work_dir/header_info.json > $work_dir/header_info.json.gz
    if [ $? -ne 0 ]; then
        log ERROR "Compressed version json fail!"
        exit 1
    fi

    log INFO "Encrypt version json"
    dd if=$work_dir/header_info.json.gz bs=1 skip=10 of=$work_dir/header_info.json.gz.bin
    if [ $? -ne 0 ]; then
        log ERROR "Encrypt version json fail!"
        exit 1
    fi

    log INFO "Pack firmware"
    local HEADER_LEN=$(wc -c $work_dir/header_info.json.gz.bin | cut -d' ' -f1)
    printf "\\$(printf "%o" $((($HEADER_LEN >> 24) & 0xFF)))" > $work_dir/$name
    printf "\\$(printf "%o" $((($HEADER_LEN >> 16) & 0xFF)))" >> $work_dir/$name
    printf "\\$(printf "%o" $((($HEADER_LEN >> 8) & 0xFF)))" >> $work_dir/$name
    printf "\\$(printf "%o" $(($HEADER_LEN & 0xFF)))" >> $work_dir/$name

    cat $work_dir/header_info.json.gz.bin >> $work_dir/$name
    cat $work_dir/firmware.iso.gz >> $work_dir/$name

    log INFO "Pack firmware success!"
    log INFO "File path: $work_dir/$name"
}

function pack_iso () {
    if [ ! -d "$unpack_dir" ]; then
        log ERROR "Not found unpack rootfs!"
        exit 1
    fi
    
    local firmware_id="$1"
    local version_arg="$2"
    local build_time="$3"
    local encrypt_flag="-v2"
    local private_key_file=""

    # Parse optional flags
    local i=4
    while [ $i -le $# ]; do
        arg="${!i}"
        case "$arg" in
            -v1|-v2|-v3|-ikmf|-qemu|-xzskip) encrypt_flag="$arg" ;;
            -p) i=$((i+1)); private_key_file="${!i}" ;;
        esac
        i=$((i+1))
    done

    pack_rootfs "$firmware_id" "$version_arg" "$build_time" "__auto_iso_grub__" "$encrypt_flag" "$private_key_file"
    if [ $? -ne 0 ]; then
        log ERROR "Update release file fail!"
        exit 1
    fi
    log INFO "Firmware size: $firmware_size"

    log INFO "Create iso"
    mkdir $work_dir/iso
    cp -rfp $iso_files/iso/* $work_dir/iso
    cp $unpack_dir/vmlinuz $work_dir/iso/boot/vmlinuz
    cp $work_dir/rootfs.img.xz.bin $work_dir/iso/boot/rootfs

    log INFO "Update grub cfg"
    sed -i "s|%version%|$version|g" $work_dir/iso/boot/grub/grub.cfg $work_dir/iso/boot/grub/grub-disk.cfg
    sed -i "s|^set ikversion=.*|set ikversion=$version|g" $work_dir/iso/boot/grub/grub.cfg $work_dir/iso/boot/grub/grub-disk.cfg
    sed -i "s|%initrd_length%|$initrd_length|g" $work_dir/iso/boot/grub/grub.cfg
    if [ $? -ne 0 ]; then
        log ERROR "Update grub cfg fail!"
        exit 1
    fi
    
    is_enterprise=$(echo "$is_enterprise" | tr ' ' '_')
    local name="iKuai8_${sysbit}_${version}${is_enterprise}_Build${build_time}.iso"

    log INFO "Build iso"
    xorriso -as mkisofs \
        -V 'CDROM' \
        -o $work_dir/$name \
        -c /boot.catalog \
        -b /boot/grub/grub-iso.img \
            -no-emul-boot \
            -boot-load-size 4 \
            -boot-info-table \
        -eltorito-alt-boot \
        -e /boot/grub/grub-efi.img \
            -no-emul-boot \
            -boot-load-size 3072 \
        -isohybrid-gpt-basdat \
        $work_dir/iso
    if [ $? -ne 0 ]; then
        log ERROR "Build iso fail!"
        exit 1
    fi

    log INFO "Build iso success!"
    log INFO "File path: $work_dir/$name"
}

function patch () {
    local file="$1"
    local out_type="$2"
    local patch_dir="$(realpath "$3")"
    local firmware_id="${4:-}"
    local version_arg="${5:-}"
    local build_time="${6:-}"
    local decode_flag="-v1"
    local public_key_file=""
    local new_public_key_file=""
    local private_key_file=""

    # Allow -v1/-v2/-v3, -u, -n, -p to appear anywhere in the argument list
    local args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do
        case "${args[i]}" in
            -v1|-v2|-v3|-ikmf|-qemu|-xzskip) decode_flag="${args[i]}" ;;
            -u) i=$((i+1)); public_key_file="${args[i]}" ;;
            -n) i=$((i+1)); new_public_key_file="${args[i]}" ;;
            -p) i=$((i+1)); private_key_file="${args[i]}" ;;
        esac
    done

    log INFO "Unpack file $file"
    unpack "$file" "$decode_flag" ${public_key_file:+-u "$public_key_file"}
    if [ $? -ne 0 ]; then
        log ERROR "Unpack file fail!"
        exit 1
    fi

    current_pwd=$(pwd)

    mkdir $work_dir

    log INFO "Run patch script .."
    mapfile -t files < <(find "$patch_dir" -maxdepth 2 -type f -name '*.sh' | sort -V)
    for f in "${files[@]}"; do
        if [ -f "$f" ]; then
            unset -f install 2>/dev/null
            unset -f script_dir 2>/dev/null

            log INFO "Switch to $unpack_dir/rootfs"
            cd $unpack_dir/rootfs

            script_dir=$(dirname "$f")
            . "$f"
            if declare -f install >/dev/null 2>&1; then
                log INFO "Running $f install"
                install
            else
                log ERROR "Not found install function in $f"
            fi
        else
            log ERROR "Not found $f file"
        fi
    done

    clean_work

    log INFO "Switch to $current_pwd"
    cd $current_pwd

    if [ "$new_public_key_file" != "" ]; then
        if [ "$public_key_file" = "" ]; then
            log ERROR "Auto patch vmlinuz requires -u OLD_PUBLIC_KEY"
            exit 1
        fi

        patch_kernel -i "$unpack_dir/vmlinuz" -o "$unpack_dir/vmlinuz" -u "$public_key_file" -n "$new_public_key_file"
        if [ $? -ne 0 ]; then
            log ERROR "Auto patch vmlinuz fail!"
            exit 1
        fi
    fi

    local pack_flag="$decode_flag"
    if [ -f "$unpack_dir/.ikmf" ]; then
        case "$(normalize_rootfs_flag "$decode_flag")" in
            -ikmf|-v1) pack_flag="-ikmf" ;;
        esac
    fi

    if [ "$out_type" = "iso" ]; then
        pack_iso "$firmware_id" "$version_arg" "$build_time" "$pack_flag" ${private_key_file:+-p "$private_key_file"}
    elif [ "$out_type" = "bin" ]; then
        pack_bin "$firmware_id" "$version_arg" "$build_time" "$pack_flag" ${private_key_file:+-p "$private_key_file"}
    fi
}

function patch_kernel () {
    local input_vmlinuz="$unpack_dir/vmlinuz"
    local output_vmlinuz="$unpack_dir/vmlinuz"
    local old_key_pem=""
    local new_key_pem=""
    local python_cmd=""

    while [ $# -gt 0 ]; do
        case "$1" in
            -i|--input)
                shift
                if [ "$1" = "" ]; then
                    log ERROR "Missing value for --input"
                    return 1
                fi
                input_vmlinuz="$1"
            ;;
            -o|--output)
                shift
                if [ "$1" = "" ]; then
                    log ERROR "Missing value for --output"
                    return 1
                fi
                output_vmlinuz="$1"
            ;;
            -u|--old-key)
                shift
                if [ "$1" = "" ]; then
                    log ERROR "Missing value for --old-key"
                    return 1
                fi
                old_key_pem="$1"
            ;;
            -n|--new-key)
                shift
                if [ "$1" = "" ]; then
                    log ERROR "Missing value for --new-key"
                    return 1
                fi
                new_key_pem="$1"
            ;;
            -h|--help)
                cat <<EOF
Usage: $0 patch_kernel -u OLD_PUBLIC_KEY -n NEW_PUBLIC_KEY [-i INPUT_VMLINUZ] [-o OUTPUT_VMLINUZ]

Patch the embedded RSA public key in a Linux vmlinuz.

Defaults:
  INPUT_VMLINUZ  : $unpack_dir/vmlinuz
  OUTPUT_VMLINUZ : same as input (patch in place)
EOF
                return 0
            ;;
            -*)
                log ERROR "Unknown option: $1"
                return 1
            ;;
            *)
                if [ "$new_key_pem" = "" ]; then
                    new_key_pem="$1"
                else
                    log ERROR "Unknown argument: $1"
                    return 1
                fi
            ;;
        esac
        shift
    done

    if [ "$old_key_pem" = "" ]; then
        log ERROR "Not found old public key file. Use: $0 patch_kernel -u OLD_PUBLIC_KEY -n NEW_PUBLIC_KEY"
        return 1
    fi

    if [ "$new_key_pem" = "" ]; then
        log ERROR "Not found new public key file. Use: $0 patch_kernel -u OLD_PUBLIC_KEY -n NEW_PUBLIC_KEY"
        return 1
    fi

    if [ ! -f "$input_vmlinuz" ]; then
        log ERROR "Input vmlinuz not found: $input_vmlinuz"
        return 1
    fi

    if [ ! -f "$old_key_pem" ]; then
        log ERROR "Old public key file not found: $old_key_pem"
        return 1
    fi

    if [ ! -f "$new_key_pem" ]; then
        log ERROR "New public key file not found: $new_key_pem"
        return 1
    fi

    if command -v python3 >/dev/null 2>&1; then
        python_cmd="python3"
    elif command -v python >/dev/null 2>&1; then
        python_cmd="python"
    else
        log ERROR "python3/python not found!"
        return 1
    fi

    mkdir -p "$(dirname "$output_vmlinuz")"

    log INFO "Patch vmlinuz public key"
    "$python_cmd" "$tools_dir/patch_vmlinuz.py" \
        "$input_vmlinuz" \
        "$output_vmlinuz" \
        --old-key "$old_key_pem" \
        --new-key "$new_key_pem"
    if [ $? -ne 0 ]; then
        log ERROR "Patch vmlinuz fail!"
        return 1
    fi

    log INFO "Patch vmlinuz success!"
    log INFO "File path: $output_vmlinuz"
}

function clean_work () {
    log INFO "Clean work dir"
    for d in "$work_dir"/*/; do
        [ -d "$d" ] || continue
        if mountpoint -q "$d"; then
            log WARN "$d is mount, umount ing..."
            umount_retry "$d"
        fi
    done
    if [ -d "$work_dir" ]; then
        rm -rf $work_dir
    fi
}

function clean_all () {
    clean_work
    log INFO "Clean unpack dir"
    if [ -d "$unpack_dir" ]; then
        rm -rf $unpack_dir
    fi
}


case "$1" in
    unpack|pack_rootfs|pack_bin|pack_iso|patch|patch_kernel)
        func="$1"
        shift
        "$func" "$@"
    ;;
    patch_kernel_ikmf|patch_kernel_xzskip)
        shift
        in_vmlinuz="${1:-$unpack_dir/vmlinuz}"
        out_vmlinuz="${2:-$unpack_dir/vmlinuz}"
        python3 "$tools_dir/patch_vmlinuz_xzskip.py" "$in_vmlinuz" "$out_vmlinuz"
    ;;
    clean)
        clean_all
        clean_rootfs_tool
    ;;
    *)
    cat <<EOF
Usage: $0 <command> [args...]

Commands:
  unpack <xxx.iso|xxx.bin> [-v1|-v2|-v3|-ikmf] [-u PUBLIC_KEY]
      unpack iso or bin file
      -u PUBLIC_KEY  Override RSA public key for v3 signature verification
      -ikmf          4.0.306+ x64: boot official kernel in QEMU and dump plaintext xz
                     IKMF images also auto-select this path without -ikmf
                     -qemu and -xzskip are aliases of -ikmf

  patch_kernel -u OLD_PUBLIC_KEY -n NEW_PUBLIC_KEY [-i INPUT_VMLINUZ] [-o OUTPUT_VMLINUZ]
      patch embedded RSA public key in vmlinuz
      default input/output is $unpack_dir/vmlinuz

  patch_kernel_ikmf [INPUT_VMLINUZ] [OUTPUT_VMLINUZ]
      4.0.306+ x64: skip IKMF decrypt when initrd is already xz, and copy
      the mapped initrd into j4m2zc/k7p9vn for stock ik_core
      default input/output is $unpack_dir/vmlinuz
      patch_kernel_xzskip is an alias

  pack_rootfs [firmware_id] [version] [build_time]
      pack rootfs

  pack_bin [firmware_id] [version] [build_time] [-v1|-v2|-v3|-ikmf] [-p PRIVATE_KEY]
      pack bin file
      -v3 -p PRIVATE_KEY  Use v3 format with specified RSA private key for signing
      -ikmf               plaintext xz + 0x194 IKMF MD5 trailer + kernel that
                          skips IKMF decrypt and fills j4m2zc/k7p9vn
                          (4.0.306+ x64, stock ik_core)
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
  $0 unpack xxx.iso
  $0 unpack xxx.iso -v2
  $0 unpack xxx.iso -v3
  $0 unpack xxx.iso -v3 -u public.pem
  $0 unpack xxx.iso -ikmf
  $0 patch_kernel -u old_public.pem -n new_public.pem
  $0 patch_kernel -i rootfs-unpack/vmlinuz -o work/vmlinuz.patched -u old_public.pem -n new_public.pem
  $0 unpack xxx.bin
  $0 pack_rootfs
  $0 pack_bin Id Version 0
  $0 pack_bin Id Version 0 -v3 -p private.pem
  $0 pack_bin Id Version 0 -ikmf
  $0 pack_iso
  $0 pack_iso "" "" "" -v3 -p private.pem
  $0 patch xxx.iso iso patch_dir
  $0 patch xxx.iso iso patch_dir "" "" "" -v3 -u old_public.pem -n new_public.pem -p private.pem
  $0 patch xxx.bin bin patch_dir "" "" 202509221910
EOF
    exit 1
    ;;
esac
