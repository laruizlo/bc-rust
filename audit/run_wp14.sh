#!/usr/bin/env bash
# Re-runs the audit tree's own evidence at the pin (plan WP14.3 and its gate) from a checkout.
#
#   audit/run_wp14.sh                 # everything; about 20 minutes on two cores, half of it the
#                                     # debug differential (an 8192-bit CRT is slow unoptimised)
#   SCALE=0.25 audit/run_wp14.sh      # a quicker differential run
#   MEMCHECK=0 audit/run_wp14.sh      # without Valgrind
#   PATH=<toolchain>/bin:$PATH CARGO_TARGET_DIR=<dir> audit/run_wp14.sh     # another toolchain
#
# Inputs, beside the bc-rust checkout unless the variables say otherwise:
#   WYCHEPROOF  C2SP/wycheproof checkout                           (default ../wycheproof)
#   ACVP        usnistgov/ACVP-Server checkout, gen-val/json-files (default ../ACVP-Server)
#   RFC         directory with rfc8017.txt and rfc5869.txt         (default ../specs/rfc)
#   PYDEPS      a `pip install --target` directory holding `cryptography`; optional, enables
#               the OpenSSL cross-check and the regeneration check of the short-modulus data
# Python runs with -I: the vector directories are untrusted input.
#
# The gate (plan WP14.3): the model's self-test passes; upstream's unit tests pass inside the
# harness; every memcheck mode's control scan is reported; `ctx_public` is reported. No result
# of WP14.4 is written down before this script says so.
set -uo pipefail
cd "$(dirname "$0")/.."
WYCHEPROOF=${WYCHEPROOF:-../wycheproof}
ACVP=${ACVP:-../ACVP-Server}
RFC=${RFC:-../specs/rfc}
SCALE=${SCALE:-1.0}
MEMCHECK=${MEMCHECK:-1}
status=0
step() { printf '\n=== %s\n' "$*"; }
run() { "$@" || { echo "FAILED: $*"; status=1; }; }

step "1. baseline"
echo "HEAD $(git rev-parse HEAD)  crypto/rsa tree $(git rev-parse HEAD:crypto/rsa)  branch $(git rev-parse --abbrev-ref HEAD)"
git merge-base --is-ancestor b7e46cb HEAD 2>/dev/null && echo "the first pass's commit b7e46cb is an ancestor of HEAD"
run sha256sum --quiet -c audit/baseline.sha256 && echo "audit/baseline.sha256: all $(wc -l < audit/baseline.sha256) files match"
echo "toolchain: $(rustc --version); $(cargo --version)"

step "2. reference model: known answers"
run python3 -I audit/ref/selftest.py --rfc "$RFC" --wycheproof "$WYCHEPROOF" --acvp "$ACVP" --require-all
if [ -n "${PYDEPS:-}" ]; then
    step "2b. reference model against OpenSSL"
    run python3 -I audit/ref/selftest_openssl.py --deps "$PYDEPS"
    step "2c. the short-modulus data of finding F-02 are still what the model and OpenSSL give"
    tmp=$(mktemp) && python3 -I audit/ref/make_short_modulus_probe.py --deps "$PYDEPS" > "$tmp" \
        && run cmp "$tmp" audit/harness/tests/data/short_modulus.rs; rm -f "$tmp"
fi

step "3. harness: upstream's unit tests compiled inside it (debug, release), probes, compile checks"
( cd audit/harness
  cargo test --lib 2>&1 | grep -E "^test result|^error" ; test "${PIPESTATUS[0]}" -eq 0 || exit 1
  cargo test --release --lib 2>&1 | grep -E "^test result|^error" ; test "${PIPESTATUS[0]}" -eq 0 || exit 1
  cargo test --test probes 2>&1 | grep -E "^test result|^error|FAILED|panicked at tests" ; test "${PIPESTATUS[0]}" -eq 0 || exit 1
  cargo test --release --test probes 2>&1 | grep -E "^test result|^error|FAILED|panicked at tests" ; test "${PIPESTATUS[0]}" -eq 0 || exit 1
  ./check_compile.sh | tail -n 1; test "${PIPESTATUS[0]}" -eq 0 || exit 1
  cargo build --bins 2>&1 | grep -E "^error" ; cargo build --release --bins 2>&1 | grep -E "^error"
  T=${CARGO_TARGET_DIR:-target}; test -x "$T/debug/diff_runner" && test -x "$T/release/diff_runner" ) || { echo "FAILED: harness"; status=1; }
T=${CARGO_TARGET_DIR:-audit/harness/target}

step "4. differential run, release build (scale $SCALE)"
run python3 -I audit/ref/gen_cases.py --runner "$T/release/diff_runner" --profile release --scale "$SCALE"
step "5. differential run, debug build with debug assertions (scale 0.05)"
run python3 -I audit/ref/gen_cases.py --runner "$T/debug/diff_runner" --profile debug --scale 0.05 --seed 7

step "6. the lines the audit's documents cite"
audit/wp11_lines.sh --check | grep -v '^ok ' | grep -v '^$' | head -n 12; test "${PIPESTATUS[0]}" -eq 0 || { echo "FAILED: a cited line is stale"; status=1; }

if [ "$MEMCHECK" = 1 ] && command -v valgrind >/dev/null; then
    step "7. taint under Valgrind memcheck, RSA-2048 (SIZES=... for the others)"
    run audit/harness/check_ct_memcheck.sh
    step "8. the binary: conditional instructions on the context chain (informative)"
    audit/harness/show_ct_instructions.sh | cut -c1-150
else
    step "7. taint under Valgrind memcheck: skipped (MEMCHECK=$MEMCHECK, valgrind $(command -v valgrind >/dev/null && echo present || echo absent)); the gate is not met without it"
fi

printf '\n%s\n' "$([ $status -eq 0 ] && echo 'WP14.3 EVIDENCE: ALL STEPS PASSED' || echo 'WP14.3 EVIDENCE: SOME STEP FAILED')"
exit $status
