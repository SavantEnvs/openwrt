#!/usr/bin/env bash
#
# mayhem/build.sh — build the fuzz targets and the oracle binaries for OpenWrt's standalone host
# tools (nvram, kconfig `conf`, bcm4908img, osafeloader). OpenWrt itself is a build system, so
# these libc-only C utilities are the parsers that can be fuzzed without a toolchain build.
#
# Runs as `mayhem` in /mayhem (the repo root, == $SRC). Offline and idempotent: it compiles
# straight from the tracked sources into mayhem/build/ (gitignored) and /mayhem/<name>.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT=/mayhem
B="$SRC/mayhem/build"
rm -rf "$B"
mkdir -p "$B/fuzz" "$B/test"

NVRAM=package/utils/nvram/src
KCONF=scripts/config
BCM=package/utils/bcm4908img/src
OSAFE=package/utils/osafeloader/src

# The fuzzed project code is compiled with the sanitizers, DWARF 3 and SanCov (-fsanitize=fuzzer-no-link);
# libFuzzer's own main/runtime is linked only where a harness has LLVMFuzzerTestOneInput.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 -w"

compile() { # compile <out.o> <src.c> [extra flags]
  local o="$1" s="$2"; shift 2
  $CC $FUZZ_CFLAGS "$@" -c "$s" -o "$o"
}

# LeakSanitizer is turned off at build time for every ASan binary (leaks are not the bug class we hunt).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/fuzz/lsan_off.o"

# ---- fuzz_nvram (libFuzzer) --------------------------------------------------------------------
compile "$B/fuzz/nvram.o" "$NVRAM/nvram.c" -I"$NVRAM"
compile "$B/fuzz/nvram_crc.o" "$NVRAM/crc.c" -I"$NVRAM"
compile "$B/fuzz/fuzz_nvram.o" mayhem/fuzz_nvram.c -I"$NVRAM"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$B/fuzz/fuzz_nvram.o" "$B/fuzz/nvram.o" "$B/fuzz/nvram_crc.o" "$B/fuzz/lsan_off.o" -o "$OUT/fuzz_nvram"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" \
    "$B/fuzz/fuzz_nvram.o" "$B/fuzz/nvram.o" "$B/fuzz/nvram_crc.o" "$B/fuzz/lsan_off.o" -o "$OUT/fuzz_nvram-standalone"

# ---- kconfig_conf (raw file-input: conf --olddefconfig -r @@ over a fixed Kconfig) -------------
KOBJS=""
# preprocess.c's variable_all_del() walks an empty list with list_for_each_entry_safe() over the bare
# list head, a null-pointer member access UBSan halts on for EVERY input (benign upstream list idiom,
# kconfig's own Linux list.h); relax only `null,object-size` on that one file so the target can fuzz.
for f in conf confdata expr lexer.lex menu parser.tab preprocess symbol util; do
  extra=""; [ "$f" = preprocess ] && extra="-fno-sanitize=null,object-size"
  compile "$B/fuzz/kconf_$f.o" "$KCONF/$f.c" -I"$KCONF" $extra
  KOBJS="$KOBJS $B/fuzz/kconf_$f.o"
done
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $KOBJS "$B/fuzz/lsan_off.o" -o "$OUT/kconfig_conf"

# ---- bcm4908img, osafeloader (raw file-input CLIs) --------------------------------------------
compile "$B/fuzz/bcm4908img.o" "$BCM/bcm4908img.c"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/fuzz/bcm4908img.o" "$B/fuzz/lsan_off.o" -o "$OUT/bcm4908img"

compile "$B/fuzz/osafeloader.o" "$OSAFE/osafeloader.c" -I"$OSAFE"
compile "$B/fuzz/osafeloader_md5.o" "$OSAFE/md5.c" -I"$OSAFE"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/fuzz/osafeloader.o" "$B/fuzz/osafeloader_md5.o" "$B/fuzz/lsan_off.o" \
    -o "$OUT/osafeloader"

# ---- oracle binaries: the same tools, NORMAL flags, no sanitizers --------------------------------
TEST_CFLAGS="-O2 -w $COVERAGE_FLAGS"
$CC $TEST_CFLAGS -I"$NVRAM" mayhem/nvram_kat.c "$NVRAM/nvram.c" "$NVRAM/crc.c" -o "$B/test/nvram_kat"
$CC $TEST_CFLAGS -I"$KCONF" "$KCONF"/{conf,confdata,expr,lexer.lex,menu,parser.tab,preprocess,symbol,util}.c \
    -o "$B/test/conf"
$CC $TEST_CFLAGS "$BCM/bcm4908img.c" -o "$B/test/bcm4908img"
$CC $TEST_CFLAGS -I"$OSAFE" "$OSAFE/osafeloader.c" "$OSAFE/md5.c" -o "$B/test/osafeloader"
