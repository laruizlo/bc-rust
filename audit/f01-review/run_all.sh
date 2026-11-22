#!/usr/bin/env bash
# Regenerates every log REPORT.md cites, with fixed seeds, and prints one PASS/FAIL line per check.
#
#   ./run_all.sh [SNAPSHOT_PATH]        # default: /home/claude/f01-review/src
#
# Checks (F-01, second review):
#   lemma          information-content lemma + prime recovery, pure Python          (py/lemma.py)
#   faithful       instrumented copy == real crate (mont_n_prime, mod_pow)          (harnessA)
#   recover-real   p,q recovered from the real new()'s branch decisions + public n  (harnessA+recover.py)
#   asm-branch     release binary: double_mod_n select is a jcc on the sub borrow, no cmov (harnessB)
#   vg-signcore    memcheck: new()->mod_pow over a secret modulus branches on it     (positive)
#   vg-control     memcheck: explicit var-time control branches on the secret        (positive control)
#   vg-ctsub       memcheck: the crate's branch-free sub_mod over a secret is CLEAN  (clean control)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SNAP="${1:-/home/claude/f01-review/src}"
SNAP="$(cd "$SNAP" && pwd)"
export CARGO_TARGET_DIR="$HERE/target"
export CARGO_HOME="$HERE/.cargo-home"
mkdir -p "$HERE/logs"
declare -A R   # results

say() { printf '%-14s %s\n' "$1" "$2"; }

# Point both harnesses' path-deps at $SNAP (idempotent).
for toml in "$HERE/harnessA/Cargo.toml" "$HERE/harnessB/Cargo.toml"; do
  sed -i -E "s#path = \"[^\"]*crypto/rsa\"#path = \"$SNAP/crypto/rsa\"#; \
             s#path = \"[^\"]*crypto/ec\"#path = \"$SNAP/crypto/ec\"#; \
             s#path = \"[^\"]*crypto/utils\"#path = \"$SNAP/crypto/utils\"#" "$toml"
done

# 1. Lemma (no snapshot needed).
if python3 -I "$HERE/py/lemma.py" >"$HERE/logs/lemma.log" 2>&1 && grep -q '^ALL-PASS' "$HERE/logs/lemma.log"; then
  R[lemma]=PASS; else R[lemma]=FAIL; fi

# 2+3. Harness A: faithfulness + recovery.
( cd "$HERE/harnessA" && cargo build --release --quiet ) >"$HERE/logs/harnessA-build.log" 2>&1
if "$CARGO_TARGET_DIR/release/f01a" >"$HERE/logs/harnessA.log" 2>&1 && grep -q '^HARNESS-A-ALL-PASS' "$HERE/logs/harnessA.log"; then
  R[faithful]=PASS; else R[faithful]=FAIL; fi
cp "$HERE/harnessA/recover_input.txt" "$HERE/logs/recover_input.txt" 2>/dev/null
if python3 -I "$HERE/py/recover.py" "$HERE/harnessA/recover_input.txt" >"$HERE/logs/recover.log" 2>&1 \
   && grep -q '^RECOVER-ALL-PASS' "$HERE/logs/recover.log"; then
  R[recover-real]=PASS; else R[recover-real]=FAIL; fi

# 4. Harness B: release binary, classify the double_mod_n select.
( cd "$HERE/harnessB" && cargo build --release --quiet ) >"$HERE/logs/harnessB-build.log" 2>&1
SO="$CARGO_TARGET_DIR/release/libf01b.so"
objdump -d --no-show-raw-insn "$SO" >"$HERE/logs/f01b_full.asm" 2>&1
awk '/<f01_sign_core>:/{on=1} on{print} on&&/^$/{exit}' "$HERE/logs/f01b_full.asm" >"$HERE/logs/f01_sign_core.asm"
# include any out-of-line pow2_mod symbol too (inlining varies)
awk '/pow2_mod.*>:/{on=1} on{print} on&&/^$/{exit}' "$HERE/logs/f01b_full.asm" >>"$HERE/logs/f01_sign_core.asm"
CMOV=$(grep -cE ':[[:space:]]+cmov' "$HERE/logs/f01_sign_core.asm")
SUBCALL=$(grep -cE 'nat3sub' "$HERE/logs/f01_sign_core.asm")
BORROWBR=$(grep -cE ':[[:space:]]+cmpq[[:space:]]+\$0x0,0x[0-9a-f]+\(%rsp\)' "$HERE/logs/f01_sign_core.asm")
if [ "$CMOV" -eq 0 ] && [ "$SUBCALL" -ge 1 ] && [ "$BORROWBR" -ge 1 ]; then
  R[asm-branch]=PASS; else R[asm-branch]=FAIL; fi
echo "asm: cmov=$CMOV nat::sub-calls=$SUBCALL borrow-cmpq-branches=$BORROWBR" >"$HERE/logs/asm-classify.log"

# 5-7. Valgrind taint with controls.
if command -v valgrind >/dev/null && gcc -O0 -g -I/usr/include "$HERE/harnessB/memcheck_harness.c" \
     -o "$CARGO_TARGET_DIR/memcheck_harness" "$SO" -Wl,-rpath,"$CARGO_TARGET_DIR/release" 2>"$HERE/logs/gcc.log"; then
  for mode in signcore control ctsub; do
    valgrind -q --error-exitcode=9 --track-origins=yes "$CARGO_TARGET_DIR/memcheck_harness" "$mode" \
      >"$HERE/logs/vg-$mode.log" 2>&1
    echo "$?" >"$HERE/logs/vg-$mode.rc"
  done
  # signcore and control must report (exit 9); ctsub must be clean (exit 0)
  [ "$(cat "$HERE/logs/vg-signcore.rc")" = 9 ] && R[vg-signcore]=PASS || R[vg-signcore]=FAIL
  [ "$(cat "$HERE/logs/vg-control.rc")" = 9 ]  && R[vg-control]=PASS  || R[vg-control]=FAIL
  [ "$(cat "$HERE/logs/vg-ctsub.rc")" = 0 ]    && R[vg-ctsub]=PASS    || R[vg-ctsub]=FAIL
else
  R[vg-signcore]=FAIL; R[vg-control]=FAIL; R[vg-ctsub]=FAIL
fi

echo "------------------------------------------------------------"
fail=0
for k in lemma faithful recover-real asm-branch vg-signcore vg-control vg-ctsub; do
  say "$k" "${R[$k]:-FAIL}"
  [ "${R[$k]:-FAIL}" = PASS ] || fail=1
done
echo "------------------------------------------------------------"
[ "$fail" -eq 0 ] && echo "ALL CHECKS PASS" || echo "SOME CHECKS FAILED"
exit "$fail"
