#!/usr/bin/env bash
#
# mayhem/build.sh — build the fuzz target and the oracle binary for ead-client, the client of OpenWrt's
# Emergency Access Daemon (package/network/services/ead/src). The client is compiled into the harness
# together with its tinysrp (SRP) library and ead-crypt, straight from the tracked sources.
#
# Runs as `mayhem` in /mayhem (the repo root, == $SRC). Offline and idempotent: everything is built
# into mayhem/build/ (gitignored) and /mayhem/<name>.
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

EAD=package/network/services/ead/src

# Old K&R-style code: tinysrp predates ANSI prototypes, and its configure script is from 2001.
LEGACY="-w -Wno-implicit-function-declaration -Wno-implicit-int -Wno-int-conversion -std=gnu89"

# tinysrp is configured and built out of tree (its configure writes config.h and Makefile next to it).
build_tinysrp() { # build_tinysrp <dir> <cflags>
  local d="$1" cf="$2"
  cp -r "$EAD/tinysrp" "$d"
  (cd "$d" && CC="$CC" CFLAGS="$cf" ./configure >/dev/null && make -j"$MAYHEM_JOBS" CC="$CC" CFLAGS="$cf" libtinysrp.a >/dev/null)
}

FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 $LEGACY"
build_tinysrp "$B/fuzz/tinysrp" "$FUZZ_CFLAGS"
INC="-I$EAD -I$B/fuzz/tinysrp"

# LeakSanitizer is turned off at build time for every ASan binary (leaks are not the bug class we hunt).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/fuzz/lsan_off.o"

# ---- fuzz_ead_client (libFuzzer) ---------------------------------------------------------------
$CC $FUZZ_CFLAGS $INC -c "$EAD/ead-crypt.c" -o "$B/fuzz/ead-crypt.o"
$CC $FUZZ_CFLAGS $INC -c mayhem/fuzz_ead_client.c -o "$B/fuzz/fuzz_ead_client.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$B/fuzz/fuzz_ead_client.o" "$B/fuzz/ead-crypt.o" "$B/fuzz/tinysrp/libtinysrp.a" "$B/fuzz/lsan_off.o" \
    -o "$OUT/fuzz_ead_client"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" \
    "$B/fuzz/fuzz_ead_client.o" "$B/fuzz/ead-crypt.o" "$B/fuzz/tinysrp/libtinysrp.a" "$B/fuzz/lsan_off.o" \
    -o "$OUT/fuzz_ead_client-standalone"

# ---- oracle binary: the same client code, NORMAL flags, no sanitizers --------------------------
TEST_CFLAGS="-O2 $COVERAGE_FLAGS $LEGACY"
build_tinysrp "$B/test/tinysrp" "$TEST_CFLAGS"
TINC="-I$EAD -I$B/test/tinysrp"
$CC $TEST_CFLAGS $TINC -c "$EAD/ead-crypt.c" -o "$B/test/ead-crypt.o"
$CC $TEST_CFLAGS $TINC mayhem/ead_kat.c "$B/test/ead-crypt.o" "$B/test/tinysrp/libtinysrp.a" -o "$B/test/ead_kat"
