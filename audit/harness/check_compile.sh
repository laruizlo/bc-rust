#!/usr/bin/env bash
# Compile-time facts, checked by compiling. Each program named fail_* must fail to build with
# the error code and the text after `// expect:` on its first line (`CODE | text`, or text
# alone); each pass_* must build, and is the control of its family: it shows a failure is
# about what the fail program says and not about the program itself.
#
# Two sources: the files compile_checks/*.rs, and the families compile_checks/generated.py
# writes (findings F-04 and F-06, SHA-1 signing). Every program is *built*, not checked: a
# `const` assertion fires when the instance is generated (error E0080), which `cargo check`
# does not do.
#
#   ./check_compile.sh              # all
#   ./check_compile.sh f06          # the programs whose name contains f06
set -uo pipefail
cd "$(dirname "$0")"
filter=${1:-}
mkdir -p examples
probe=compile_probe_$$          # its own name, so that two toolchains can run this at once
status=0; n_ok=0; n_fail=0
run() {   # name, file
    local name=$1 src=$2 want code text out rc
    cp "$src" "examples/$probe.rs"
    out=$(cargo build --quiet --example "$probe" 2>&1); rc=$?
    case "$name" in
        fail_*)
            want=$(sed -n '1s|^// expect: ||p' "$src")
            if [[ "$want" == *" | "* ]]; then code=${want%% | *}; text=${want#* | }; else code='E[0-9]*'; text=$want; fi
            if [ $rc -ne 0 ] && grep -q "error\[$code\]" <<<"$out" && grep -qF -- "$text" <<<"$out"; then
                echo "ok   $name: does not build ($(grep -m1 -o 'error\[E[0-9]*\]' <<<"$out")${text:+, mentions \"$text\"})"; n_ok=$((n_ok+1))
            else
                echo "FAIL $name: expected error[$code] mentioning \"$text\" (cargo exit $rc; got: $(grep -m1 '^error' <<<"$out"))"; status=1; n_fail=$((n_fail+1))
            fi ;;
        pass_*)
            if [ $rc -eq 0 ]; then echo "ok   $name: builds"; n_ok=$((n_ok+1))
            else echo "FAIL $name: expected to build"; grep -m5 '^error' <<<"$out"; status=1; n_fail=$((n_fail+1)); fi ;;
    esac
}
for f in compile_checks/*.rs; do
    name=$(basename "$f" .rs)
    [[ -z "$filter" || "$name" == *"$filter"* ]] && run "$name" "$f"
done
tmp=$(mktemp)
for name in $(python3 -I compile_checks/generated.py list); do
    [[ -z "$filter" || "$name" == *"$filter"* ]] || continue
    python3 -I compile_checks/generated.py show "$name" > "$tmp"
    run "$name" "$tmp"
done
rm -f "examples/$probe.rs" "$tmp"; rmdir examples 2>/dev/null
echo "COMPILE CHECKS: $n_ok as expected, $n_fail not"
exit $status
