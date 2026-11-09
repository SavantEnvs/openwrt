#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer oracle for ead-client's reply handlers, built by mayhem/build.sh with
# NORMAL flags (no sanitizers) into mayhem/build/test/ead_kat. The tool delivers a valid pong, prime and
# B reply on the client's socket and prints what the client's own handlers made of them; each part is
# compared with the committed golden, so a no-op or exit(0) "fix" fails every check.
# OpenWrt itself ships no unit tests for ead.
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

KAT="$SRC/mayhem/build/test/ead_kat"
G="$SRC/mayhem/golden/ead_kat.txt"
[ -x "$KAT" ] || { echo "missing $KAT — mayhem/build.sh did not build it" >&2; emit_ctrf "openwrt-kat" 0 1 0; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
passed=0 failed=0

"$KAT" > actual.txt 2> err.txt; rc=$?

check() { # check <name> <grep pattern selecting that part of the output>
  grep -E -- "$2" "$G" > want.part
  grep -E -- "$2" actual.txt > got.part
  if [ -s want.part ] && cmp -s want.part got.part; then
    passed=$((passed + 1)); echo "ok   $1"
  else
    failed=$((failed + 1)); echo "FAIL $1"; diff want.part got.part | head -10
  fi
}

if [ "$rc" -eq 0 ]; then
  passed=$((passed + 1)); echo "ok   ead_kat runs"
else
  failed=$((failed + 1)); echo "FAIL ead_kat exited $rc"; head -3 err.txt
fi
check "pong reply (node list line, auth type, session id)" '^(1a2b:|pong )'
check "prime reply (salt, parameter set, md5 salt)" '^(prime |salt=|pw_salt=)'
check "B reply (number copied from the wire)" '^(b |B=)'

emit_ctrf "openwrt-kat" "$passed" "$failed" 0
