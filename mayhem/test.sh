#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer oracle for the host tools mayhem/build.sh builds with NORMAL flags
# (no sanitizers) into mayhem/build/test: libnvram, kconfig `conf`, bcm4908img and osafeloader.
# Each check runs the real tool over a committed fixture (mayhem/fixtures) and compares its output
# with a committed golden (mayhem/golden), so a no-op or exit(0) "fix" fails every check.
# OpenWrt itself ships no unit tests for these tools.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

T="$SRC/mayhem/build/test"
F="$SRC/mayhem/fixtures"
G="$SRC/mayhem/golden"
for b in nvram_kat conf bcm4908img osafeloader; do
  [ -x "$T/$b" ] || { echo "missing $T/$b — mayhem/build.sh did not build it" >&2; emit_ctrf "openwrt-kat" 0 1 0; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
passed=0 failed=0

check() { # check <name> <golden-file> <actual-file>
  if [ -s "$3" ] && cmp -s "$2" "$3"; then
    passed=$((passed + 1)); echo "ok   $1"
  else
    failed=$((failed + 1)); echo "FAIL $1"; diff "$2" "$3" | head -10
  fi
}

# check_rc <name> <expected rc> <expected stderr substring> <stderr-file> <actual rc>
check_rc() {
  if [ "$5" -eq "$2" ] && grep -qF -- "$3" "$4"; then
    passed=$((passed + 1)); echo "ok   $1"
  else
    failed=$((failed + 1)); echo "FAIL $1 (rc=$5, want $2 with '$3')"; head -3 "$4"
  fi
}

# libnvram: parse a fixture, edit + commit a copy, re-read it (var values, sdram defaults, header len + crc8)
"$T/nvram_kat" "$F/nvram.bin" > nvram.out 2>&1
check "nvram parse/commit" "$G/nvram.txt" nvram.out

# bcm4908img: image layout, CRC32 and the bootfs JFFS2 listing
"$T/bcm4908img" info -i "$F/bcm4908.img" > bcm_info.out 2>&1
check "bcm4908img info" "$G/bcm4908_info.txt" bcm_info.out
"$T/bcm4908img" bootfs -i "$F/bcm4908.img" ls > bcm_ls.out 2>&1
check "bcm4908img bootfs ls" "$G/bcm4908_ls.txt" bcm_ls.out

cp "$F/bcm4908.img" bad.img
printf '\001' | dd of=bad.img bs=1 seek=100 conv=notrunc 2>/dev/null
"$T/bcm4908img" info -i bad.img > /dev/null 2> bcm_bad.err; rc=$?
check_rc "bcm4908img rejects a corrupted image" 185 "Invalid data crc32" bcm_bad.err "$rc"

# osafeloader: MD5-protected SafeLoader image with its partition table
"$T/osafeloader" info "$F/safeloader.bin" > safe.out 2>&1
check "osafeloader info" "$G/safeloader_info.txt" safe.out

cp "$F/safeloader.bin" bad.bin
printf '\001' | dd of=bad.bin bs=1 seek=100 conv=notrunc 2>/dev/null
"$T/osafeloader" info bad.bin > /dev/null 2> safe_bad.err; rc=$?
check_rc "osafeloader rejects a corrupted image" 251 "invalid MD5" safe_bad.err "$rc"

# kconfig conf: apply a .config to the fixed Kconfig (dependencies, selects, ranges, defaults)
mkdir conf && (cd conf && "$T/conf" -s -r "$F/kconfig.config" --olddefconfig "$SRC/mayhem/kconfig_conf/Kconfig" > ../conf.out 2>&1; echo $? > ../conf.rc)
if [ -f conf/.config ]; then cp conf/.config conf.config; else : > conf.config; fi
check "kconfig olddefconfig .config" "$G/kconfig.config" conf.config
mkdir conf2 && (cd conf2 && "$T/conf" -s --allyesconfig "$SRC/mayhem/kconfig_conf/Kconfig" > ../conf2.out 2>&1)
if [ -f conf2/.config ]; then cp conf2/.config conf2.config; else : > conf2.config; fi
check "kconfig allyesconfig .config" "$G/kconfig_allyes.config" conf2.config

emit_ctrf "openwrt-kat" "$passed" "$failed" 0
