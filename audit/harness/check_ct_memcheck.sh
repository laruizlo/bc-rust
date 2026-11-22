#!/usr/bin/env bash
# Dynamic taint check of the RSA private-key path under Valgrind memcheck (plan 5.5 step 2).
# Builds src/bin/ct_memcheck.rs in the release configuration (plus line tables) and runs each
# mode with its secrets undefined. memcheck reports each conditional jump and each address
# that depends on an undefined value; judge_memcheck.py reads where.
#
#   ./check_ct_memcheck.sh                        # RSA-2048
#   SIZES="2048 3072 4096 8192" ./check_ct_memcheck.sh
#   MODES="ctx_secret crt_key" ./check_ct_memcheck.sh
#   PATH=<toolchain>/bin:$PATH CARGO_TARGET_DIR=<dir> ./check_ct_memcheck.sh   # another toolchain
#
# Expectations at 30cbbab, where finding F-01 is fixed upstream:
#   ctx_public         reported  the variable-time constructor over an undefined modulus: a
#                                control on the code, with the doubling chain among the places
#   ctx_secret, crt_key, crt_base, crt_raw_key, mod_pow, reduce_wide, sub_mod, mul_mod,
#   recombine, public_exp_base
#                      clean     and no mode may report the doubling chain
#   sign, sign_pss, rsasve_recover
#                      whole operations, judged against declassified.txt: "declassified",
#                      every report being a register line whose argument is written
#   oaep_decrypt, oaep_decrypt_bad
#                      "result-handling": memcheck reports what rsaes_oaep.rs does with the
#                      decoding's outcome and the recovered key's length after decode_out has
#                      returned them, and nothing in the CRT, the mask generation or the
#                      decoding. The reports are listed: they are plan gap G16, to be argued
#                      or fixed in WP5, and this script only pins where they are.
# The script fails if an outcome differs from the stated one in either direction. Every mode
# ends with a variable-time control scan over the values it passed to the code under test;
# memcheck must report that scan, or the mode is VOID: its inputs were not undefined and its
# silence means nothing.
set -uo pipefail
cd "$(dirname "$0")"
command -v valgrind >/dev/null || { echo "FAIL: valgrind is not installed"; exit 2; }
cargo build --quiet --profile memcheck --bin ct_memcheck || exit 2
T=${CARGO_TARGET_DIR:-target}
BIN=$T/memcheck/ct_memcheck
SIZES=${SIZES:-2048}
ALL="control ctx_secret ctx_public crt_key crt_base crt_raw_key mod_pow reduce_wide sub_mod mul_mod recombine public_exp_base sign sign_pss rsasve_recover oaep_decrypt oaep_decrypt_bad"
MODES=${MODES:-$ALL}
echo "toolchain: $(rustc --version); $(valgrind --version); $(uname -m)"
status=0
mkdir -p "$T/memcheck-logs"
for size in $SIZES; do
    KEY=$("$BIN" genkey "$size") || { echo "FAIL: no key at RSA-$size"; exit 2; }
    echo "RSA-$size"
    printf '%-17s %-13s %-13s %s\n' mode expected got "where memcheck reports, innermost frame first (control scan apart)"
    for mode in $MODES; do
        case "$mode" in
            ctx_public) want=reported; kind=kernel ;;
            sign|sign_pss|rsasve_recover) want=declassified; kind=whole ;;
            oaep_decrypt|oaep_decrypt_bad) want=result-handling; kind=whole ;;
            *) want=clean; kind=kernel ;;
        esac
        log=$T/memcheck-logs/$size-$mode.log
        # shellcheck disable=SC2086
        valgrind -q "$BIN" "$mode" "$size" $KEY >"$log" 2>&1; rc=$?
        if [ $rc -ne 0 ]; then
            got="exit-$rc"; detail=$(tail -n 2 "$log" | tr '\n' ' ')
        else
            IFS=$'\t' read -r got detail < <(python3 -I judge_memcheck.py "$kind" "$log" ../../crypto declassified.txt)
        fi
        printf '%-17s %-13s %-13s %s\n' "$mode" "$want" "$got" "$detail"
        [ "$want" = "$got" ] || status=1
        chain=$(grep -c 'double_mod_n_vartime\|pow2_mod_vartime' <<<"$detail" || true)
        if [ "$mode" = ctx_public ]; then
            [ "$chain" -gt 0 ] || { echo "  ^ expected the variable-time doubling chain among the reports"; status=1; }
        else
            [ "$chain" -eq 0 ] || { echo "  ^ the variable-time doubling chain is reported on a path that must not run it"; status=1; }
        fi
    done
done
echo "(every mode also reports the control scan over its own tainted inputs; a mode where it does not is VOID)"
[ $status -eq 0 ] && echo "MEMCHECK: every mode as expected" || echo "MEMCHECK: UNEXPECTED RESULT"
exit $status
