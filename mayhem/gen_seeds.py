#!/usr/bin/env python3
"""Regenerate the committed seeds/fixtures under mayhem/<target>/testsuite and mayhem/fixtures.

Run from the repo root: python3 mayhem/gen_seeds.py. The outputs are committed; build.sh and
test.sh never run this.
"""
import hashlib
import os
import re
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
M = os.path.join(ROOT, "mayhem")


def put(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


# ---- nvram: "FLSH" header + name=value\0...\0\0, crc8 over header[9:len] ---------------------------
def crc8_table():
    src = open(os.path.join(ROOT, "package/utils/nvram/src/crc.c")).read()
    body = src[src.index("crc8_table[256]"):]
    body = body[body.index("{"):body.index("};")]
    tbl = [int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", body)]
    assert len(tbl) == 256
    return tbl


def nvram_image(variables, sdram=(0x0003, 0x0009, 0x0000, 0), pad_to=None):
    tbl = crc8_table()
    data = b"".join(f"{k}={v}".encode() + b"\0" for k, v in variables) + b"\0"
    data += b"\0" * (-(len(data) + 20) % 4)
    length = 20 + len(data)
    init, config, refresh, ncdl = sdram
    crc_ver_init = (1 << 8) | (init << 16)
    config_refresh = config | (refresh << 16)
    hdr = struct.pack("<IIIII", 0x48534C46, length, crc_ver_init, config_refresh, ncdl)
    crc = 0xFF
    for b in (hdr + data)[9:length]:
        crc = tbl[(crc ^ b) & 0xFF]
    hdr = struct.pack("<IIIII", 0x48534C46, length, crc_ver_init | crc, config_refresh, ncdl)
    img = hdr + data
    if pad_to:
        img += b"\xff" * (pad_to - len(img))
    return img


NV = [
    ("lan_ipaddr", "192.168.1.1"),
    ("lan_netmask", "255.255.255.0"),
    ("wan_proto", "dhcp"),
    ("et0macaddr", "00:11:22:33:44:55"),
]
put(os.path.join(M, "fixtures/nvram.bin"), nvram_image(NV, pad_to=0x200))
put(os.path.join(M, "fuzz_nvram/testsuite/basic.nvram"), nvram_image(NV, pad_to=0x200))
put(os.path.join(M, "fuzz_nvram/testsuite/sdram.nvram"),
    nvram_image(NV + [("sdram_init", "0x0419"), ("sdram_config", "0x0152"),
                      ("sdram_refresh", "0x0008"), ("sdram_ncdl", "0x5")], sdram=(0x0004, 0x000A, 0x0001, 7), pad_to=0x400))
put(os.path.join(M, "fuzz_nvram/testsuite/padded.nvram"),
    nvram_image([("boardtype", "0x04cf"), ("boardnum", "42"), ("boardrev", "0x1100"), ("ccode", "DE")],
                pad_to=0x8100))
put(os.path.join(M, "fuzz_nvram/testsuite/empty.nvram"), nvram_image([], pad_to=0x100))


# ---- bcm4908img: bootfs (JFFS2 dirents) + FF padding + UBI rootfs + crc32 tail --------------------
def jffs2_dirent(name, ino):
    nsize = len(name)
    totlen = 40 + nsize
    node = struct.pack("<HHII", 0x1985, 0xE001, totlen, 0)
    node += struct.pack("<IIII", 1, ino, ino, 0)
    node += struct.pack("<BBHII", nsize, 8, 0, 0, 0)
    node += name.encode()
    return node + b"\0" * (-totlen % 4)


def bcm4908_image(names, vendor_tail=b""):
    boot = b"".join(jffs2_dirent(n, 10 + i) for i, n in enumerate(names))
    img = boot + b"\xff" * (0x20000 - len(boot))
    img += b"\xff" * 0x20000
    img += b"UBI#" + b"\x01" + b"\0" * 251
    body = img
    raw = (~zlib.crc32(body)) & 0xFFFFFFFF
    tail = struct.pack("<IIIII", raw, 0x5732, 0x4908, 1, 1)
    return body + tail + vendor_tail


img = bcm4908_image(["cferam.000", "vmlinux.lz", "bcm94908.dtb"])
put(os.path.join(M, "fixtures/bcm4908.img"), img)
put(os.path.join(M, "bcm4908img/testsuite/boot3.img"), img)
put(os.path.join(M, "bcm4908img/testsuite/linksys.img"),
    bcm4908_image(["linksys"], vendor_tail=b"\0" * 0x1C + b".LINKSYS."))


# ---- osafeloader: be32 size + md5(salt+data) + 0x1000 vendor bytes + fwup-ptn lines -----------------
SALT = bytes([0x7A, 0x2B, 0x15, 0xED, 0x9B, 0x98, 0x59, 0x6D, 0xE5, 0x04, 0xAB, 0x44, 0xAC, 0x2A, 0x9F, 0x4E])


def safeloader(parts):
    vendor = b"vendor-info".ljust(0x1000, b"\0")
    ptns = b"".join(f"fwup-ptn {n} base 0x{b:x} size 0x{s:x}\t\r\n".encode() for n, b, s in parts)
    data = vendor + ptns
    md5 = hashlib.md5(SALT + data).digest()
    return struct.pack(">I", len(data)) + md5 + data


sl = safeloader([("os-image", 0x20000, 0x1A0000), ("file-system", 0x1C0000, 0x600000), ("partition-table", 0, 0x800)])
put(os.path.join(M, "fixtures/safeloader.bin"), sl)
put(os.path.join(M, "osafeloader/testsuite/three.safeloader"), sl)
put(os.path.join(M, "osafeloader/testsuite/one.safeloader"), safeloader([("fs-uboot", 0, 0x20000)]))


# ---- kconfig_conf: .config files against mayhem/conf/Kconfig ------------------------------------
CONF = """# Automatically generated file; DO NOT EDIT.
CONFIG_TARGET_x86=y
# CONFIG_TARGET_ath79 is not set
CONFIG_TARGET_ROOTFS_PARTSIZE=256
CONFIG_TARGET_LOADADDR=0x80080000
CONFIG_TARGET_VERSION_REPO="https://example.org/releases"
CONFIG_DEVEL=y
CONFIG_BUILD_LOG=y
# CONFIG_CCACHE is not set
CONFIG_KERNEL_DEBUG_INFO=y
CONFIG_KERNEL_SWAP=m
CONFIG_KERNEL_LOG_BUF_SHIFT=18
CONFIG_EXTRA_OPTIMIZATION="-O2"
CONFIG_IB=y
CONFIG_PACKAGE_busybox=m
CONFIG_BUSYBOX_CONFIG_FEATURE_EDITING_HISTORY=512
CONFIG_PACKAGE_openssh-server=y
CONFIG_PACKAGE_hostapd=y
CONFIG_PACKAGE_UNKNOWN_SYMBOL=y
"""
put(os.path.join(M, "fixtures/kconfig.config"), CONF.encode())
put(os.path.join(M, "kconfig_conf/testsuite/full.config"), CONF.encode())
put(os.path.join(M, "kconfig_conf/testsuite/minimal.config"),
    b"CONFIG_TARGET_ramips=y\nCONFIG_TARGET_ROOTFS_PARTSIZE=9999\nCONFIG_KERNEL_LOG_BUF_SHIFT=3\n"
    b"CONFIG_TARGET_LOADADDR=0x1\nCONFIG_PACKAGE_dropbear=n\n")
put(os.path.join(M, "kconfig_conf/testsuite/strings.config"),
    b'CONFIG_TARGET_VERSION_REPO="a \\"quoted\\" \\\\ value"\nCONFIG_EXTRA_OPTIMIZATION=""\n'
    b"CONFIG_MODULES=y\nCONFIG_SIGNED_PACKAGES=n\n# CONFIG_PACKAGE_libc is not set\n")
