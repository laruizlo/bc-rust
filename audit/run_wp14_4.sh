#!/usr/bin/env bash
# Plan WP14.4, rows F-02 to F-06: what each line of a row rests on, re-run from a checkout at
# the pin, in a release build and, for the functional lines, in a debug build as well.
#
#   audit/run_wp14_4.sh                                                    # about 12 minutes
#   PATH=<toolchain>/bin:$PATH CARGO_TARGET_DIR=<dir> audit/run_wp14_4.sh  # another toolchain
#   DEBUG=0 audit/run_wp14_4.sh                                            # release only
#
# Inputs: as audit/run_wp14.sh. PYDEPS (a `pip install --target` directory holding
# `cryptography`) is required here: row F-02 (d) has OpenSSL as its second oracle. RFC (a
# directory with rfc8017.txt) is read for row F-05. Logs go to LOGS (default
# audit/logs/wp14_4-<rustc version>), one file a step, and what this script prints to
# summary.txt there. The logs of the runs behind claude/rsa-wp14-report-2.md are on the
# branch (added with `git add -f`: audit/.gitignore ignores logs/).
#
# Row F-01 is not here: its evidence is audit/harness/check_ct_memcheck.sh at the four sizes,
# audit/harness/show_ct_instructions.sh and audit/f01-pin-check.sh.
#
# The last lines are a table, one line per line of a row, and the verdict. A line that says
# `holds` rests on a step that ran here with its control; nothing is carried from another run.
set -uo pipefail
cd "$(dirname "$0")/.."
RFC=${RFC:-../specs/rfc}
DEBUG=${DEBUG:-1}
rustc_v=$(rustc --version | awk '{print $2}')
LOGS=${LOGS:-audit/logs/wp14_4-$rustc_v}
mkdir -p "$LOGS"
exec > >(tee "$LOGS/summary.txt") 2>&1          # what this prints is kept beside the step logs
T=${CARGO_TARGET_DIR:-audit/harness/target}
declare -A R                       # step -> ok | FAIL
step() {  # name, command...: runs it, keeps its log, records its verdict
    local name=$1; shift
    local t0=$SECONDS
    if "$@" > "$LOGS/$name.log" 2>&1; then R[$name]=ok; else R[$name]=FAIL; fi
    printf '  %-34s %-4s %4ss  %s\n' "$name" "${R[$name]}" "$((SECONDS - t0))" "$(tail -n 1 "$LOGS/$name.log" | cut -c1-110)"
}
all() { local s; for s in "$@"; do [ "${R[$s]:-missing}" = ok ] || { echo "DOES NOT HOLD ($s: ${R[$s]:-not run})"; return; }; done; echo holds; }

echo "WP14.4, rows F-02 to F-06 -- $(rustc --version); $(date -u +%Y-%m-%dT%H:%MZ)"
echo "HEAD $(git rev-parse HEAD)  crypto/rsa tree $(git rev-parse HEAD:crypto/rsa)"
if sha256sum --quiet -c audit/baseline.sha256; then echo "audit/baseline.sha256: all $(wc -l < audit/baseline.sha256) files match"
else echo "BASELINE DRIFT: read the change before any result (plan 2.1)"; exit 1; fi
[ -n "${PYDEPS:-}" ] || { echo "PYDEPS is not set: row F-02 (d) needs OpenSSL through PyPI's cryptography"; exit 1; }

echo; echo "steps (log: $LOGS/<step>.log)"
profiles="release"; [ "$DEBUG" = 1 ] && profiles="release debug"
step build bash -c "cd audit/harness && cargo build --release --bins && { [ $DEBUG = 0 ] || cargo build --bins; }"
gen() { python3 -I audit/ref/gen_cases.py --runner "$T/$1/diff_runner" --profile "$1" --families "$2" --scale "$3" ${4:+--seed "$4"}; }
for p in $profiles; do
    flag=""; [ "$p" = release ] && flag="--release"
    step "probes-$p" bash -c "cd audit/harness && cargo test $flag --test probes 2>&1 | grep -E '^test |^test result|panicked at tests' ; test \${PIPESTATUS[0]} -eq 0"
    step "constructors-$p" gen "$p" constructors 1.0
    step "from-hash-lengths-$p" gen "$p" from_hash_lengths 1.0
done
# F-02 (d): the floor of 256 each way is a release run; the debug run is the same code at a
# smaller scale and without RSA-4096 and RSA-8192, whose unoptimised CRT is slow.
step pss-interop-release python3 -I audit/ref/pss_interop.py --runner "$T/release/diff_runner" --deps "$PYDEPS"
[ "$DEBUG" = 1 ] && step pss-interop-debug python3 -I audit/ref/pss_interop.py --runner "$T/debug/diff_runner" \
    --deps "$PYDEPS" --scale 0.25 --sizes 1024,1536,2048,3072 --no-floor
step search-i1 python3 -I audit/tools/listed_searches.py i1
# The same list from the compiler: every aggregate of a key type in the crate's MIR.
step mir-sites python3 -I audit/tools/mir_sites.py
step search-roles python3 -I audit/tools/listed_searches.py roles
step search-m10 python3 -I audit/tools/listed_searches.py m10
step compile-checks bash -c "cd audit/harness && ./check_compile.sh"
# The lines the report's part 2 and the proof of I1 cite: the findings' rows, and those of I1,
# N12, N13, N14, map flag 13 and the claims table. Each row is checked against a piece of its text.
step cited-lines bash -c "out=\$(audit/wp11_lines.sh --check F-02 F-03 F-04 F-05 F-06 I1 N12 N13 N14 flag13 claims); echo \"\$out\"; echo \"\$out\" | grep '^rows:'; echo \"\$out\" | grep -q '^rows: [0-9]*, stale: 0\$'"
step keygen-release gen release primality_and_keygen 1.0
[ "$DEBUG" = 1 ] && step keygen-debug gen debug primality_and_keygen 0.05 7
step limb-order python3 -I audit/ref/limb_order_check.py --runner "$T/release/diff_runner"
# F-05 row 1: the step labels against RFC 8017 section 5.2.1 as the RFC text has it; row 4:
# the figure in the comment against the product it names.
step f05-rfc-and-figure python3 -I - "$RFC/rfc8017.txt" crypto/rsa/src/rsa_core.rs crypto/rsa/src/keygen.rs <<'EOF'
import math, re, sys
rfc, core, keygen = (open(p, encoding="utf-8", errors="replace").read() for p in sys.argv[1:4])
sec = rfc[rfc.index("\n5.2.1.  RSASP1"):rfc.index("\n5.2.2.  RSAVP1")]
steps = {m.group(1): " ".join(m.group(2).split()) for m in re.finditer(r"\n {14}(\d)\.  (Let [^\n]+)", sec)}
want = {"1": "s_1 = m^dP mod p", "3": "h = (s_1 - s_2) * qInv mod p", "4": "s = s_2 + q * h"}
ok = True
for k, text in want.items():
    in_rfc = text in steps.get(k, "")
    in_code = re.search(r"// Step 2\.b\." + k + ": " + re.escape(text), core) is not None
    print(f"RFC 8017 5.2.1 step 2.b.{k}: \"{steps.get(k)}\" -- in the RFC text: {in_rfc}; the same label and formula in rsa_core.rs: {in_code}")
    ok &= in_rfc and in_code
dp = rfc[rfc.index("\n5.1.2.  RSADP"):rfc.index("\n5.2.  Signature and Verification Primitives")]
roman = re.findall(r"\n {14}(i{1,3}|iv|v)\.\s", dp)
print(f"RFC 8017 5.1.2 numbers the same sub-steps {roman}; rsa_core.rs's doc comment says \"i to iv\": {'i to iv' in core}")
ok &= roman[:4] == ["i", "ii", "iii", "iv"] and "i to iv" in core
odd = [p for p in range(3, 1024, 2) if all(p % d for d in range(3, math.isqrt(p) + 1, 2))]
share = 1 - math.prod(1 - 1 / p for p in odd)
m = re.search(r"about (\d+)% of odd candidates.*?over those\s*///\s*(\d+) primes, is (0\.\d+)", keygen, re.S)
print(f"odd primes below 1024: {len(odd)}; 1 - prod(1 - 1/p) = {share:.6f}; keygen.rs says: about {m.group(1)}%, {m.group(2)} primes, {m.group(3)}")
ok &= (m.group(2), m.group(3), m.group(1)) == (str(len(odd)), f"{share:.4f}", f"{100 * share:.0f}")
print("F-05 ROWS 1 AND 4: " + ("AS THE DOCUMENTS SAY" if ok else "MISMATCH"))
sys.exit(0 if ok else 1)
EOF

# What a step printed that a row quotes.
grab() { grep -m1 -E "$2" "$LOGS/$1.log" 2>/dev/null | sed 's/^ *//;s/  */ /g' | cut -c1-220; }
echo; echo "figures"
for p in $profiles; do
    echo "  constructors, $p: $(grab constructors-$p '^  key_public') | $(grab constructors-$p '^  key_private')"
    echo "  from_hash_lengths, $p: $(grab from-hash-lengths-$p '^  from_hash')"
    echo "      $(grab from-hash-lengths-$p '^  emsa')"
    echo "  judge controls, $p: constructors: $(grab constructors-$p '^judge control'); from_hash_lengths: $(grab from-hash-lengths-$p '^judge control')"
    echo "  probes, $p: $(grab probes-$p '^test result')"
    echo "  PSS interop, $p: $(grab pss-interop-$p '^A ')"
    echo "      $(grab pss-interop-$p '^B ') | $(grab pss-interop-$p '^controls')"
done
fam() { echo "$1: $(grep -c "^ok   fail_$1" "$LOGS/compile-checks.log") fail, $(grep -c "^ok   pass_$1" "$LOGS/compile-checks.log") build"; }
echo "  compile checks: $(grab compile-checks '^COMPILE CHECKS') ($(fam f04); $(fam f06); $(fam m10); $(fam flag13); $(fam lang))"
echo "  key generation, release: $(grab keygen-release '^keygen ') (columns: match, expected, observation, MISMATCH, PANIC, NO_RESULT, HARNESS)"
echo "  listed searches: i1: $(grab search-i1 '^control:'); roles: $(grab search-roles '^control:'); m10: $(grab search-m10 '^control:')"
echo "  the compiler's list: $(grab mir-sites 'MIR bodies'); $(grab mir-sites 'places inside a key'); $(grab mir-sites '^control:')"
echo "  cited lines: $(grab cited-lines '^rows:')"

dbg() { [ "$DEBUG" = 1 ] && echo "$@"; }
echo; echo "rows"
echo "  F-02 (a) verdict = I1's predicate, every size      $(all build constructors-release $(dbg constructors-debug))"
echo "  F-02 (b) decoders and KEM wrappers, same verdict   $(all constructors-release $(dbg constructors-debug))"
echo "  F-02 (c) the first pass's short keys are refused   $(all probes-release $(dbg probes-debug))"
echo "  F-02 (d) PSS both ways, the model and OpenSSL      $(all pss-interop-release $(dbg pss-interop-debug))"
echo "  F-02 (e) I1: the proof's premises and its lines    $(all search-i1 mir-sites compile-checks cited-lines)"
echo "  F-03 (a) *_from_hash: an error, never a panic      $(all from-hash-lengths-release probes-release $(dbg from-hash-lengths-debug probes-debug))"
echo "  F-03 (b) the same through emsa_encode/emsa_verify  $(all from-hash-lengths-release $(dbg from-hash-lengths-debug))"
echo "  F-03 (c) the malformed DigestInfo                  $(all probes-release $(dbg probes-debug))"
echo "  F-03 (d) RFC 8017 9.1.1 step 3 at its boundary     $(all from-hash-lengths-release $(dbg from-hash-lengths-debug))"
echo "  F-04 (a) eight programs do not build, controls do  $(all compile-checks)"
echo "  F-04 (b) no role impl bounded by RsaSize alone     $(all search-roles)"
echo "  F-04 (c) what remains: public_exp (N14)            $(all search-roles probes-release $(dbg probes-debug))"
echo "  F-05     rows 1 to 4                               $(all cited-lines f05-rfc-and-figure keygen-release limb-order $(dbg keygen-debug))"
echo "  F-06 (a) the triples do not build, controls do     $(all compile-checks)"
echo "  F-06 (b) M10's inventory                           $(all search-m10 compile-checks)"
bad=0; for s in "${!R[@]}"; do [ "${R[$s]}" = ok ] || bad=1; done
printf '\n%s\n' "$([ $bad -eq 0 ] && echo "WP14.4 ROWS F-02 TO F-06: EVERY STEP PASSED ($rustc_v)" || echo "WP14.4 ROWS F-02 TO F-06: SOME STEP FAILED ($rustc_v)")"
exit $bad
