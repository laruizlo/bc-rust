#!/usr/bin/env bash
# Coordinator's supplementary check. NOT part of the second review, and not blind: written by the
# session that had read the first derivation, after the second reviewer had reported.
#
# The second review cites a build variation (logs/alt_pow2.asm) that its run_all.sh does not
# regenerate. This script rebuilds the reviewer's own memcheck harness (harnessB) under several build
# settings with the toolchain at hand and reports, per variant, what memcheck sees in each mode:
#   signcore  real MontgomeryContext::<16>::new -> mod_pow over an undefined modulus: must be reported
#   control   an explicit variable-time branch on the secret: must be reported (positive control)
#   ctsub     the crate's masked sub_mod over the same secret: must be clean (negative control)
# For signcore it counts the two kinds of report separately, because they are different observables:
#   jump  "Conditional jump or move depends on uninitialised value(s)"  -> a secret-dependent branch
#   addr  "Use of uninitialised value of size N"                        -> a secret-dependent address
#
#   alt_build_check.sh <reviewer tree> <checkout of bc-rust at b7e46cb> <output dir>
set -uo pipefail
W="$(cd "$1" && pwd)"; SNAP="$(cd "$2" && pwd)"; OUT="$3"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
export CARGO_HOME="$W/.cargo-home"
for toml in "$W/harnessB/Cargo.toml"; do
  sed -i -E "s#path = \"[^\"]*crypto/rsa\"#path = \"$SNAP/crypto/rsa\"#; \
             s#path = \"[^\"]*crypto/ec\"#path = \"$SNAP/crypto/ec\"#; \
             s#path = \"[^\"]*crypto/utils\"#path = \"$SNAP/crypto/utils\"#" "$toml"
done
rustc --version
printf '%-30s | %-5s | %-22s | %-7s | %-5s | %s\n' "variant (opt, lto, cgu, flags)" build "signcore rc jump addr" control ctsub verdict
# name : opt-level : lto : codegen-units : RUSTFLAGS
while IFS=: read -r name opt lto cgu flags; do
  [ -z "$name" ] && continue
  T="$OUT/$name"; mkdir -p "$T"
  ( cd "$W/harnessB" && CARGO_TARGET_DIR="$T" CARGO_PROFILE_RELEASE_OPT_LEVEL="$opt" \
      CARGO_PROFILE_RELEASE_LTO="$lto" CARGO_PROFILE_RELEASE_CODEGEN_UNITS="$cgu" RUSTFLAGS="$flags" \
      cargo build --release --quiet ) >"$T/build.log" 2>&1
  b=$?
  SO="$T/release/libf01b.so"
  if [ $b -ne 0 ] || [ ! -f "$SO" ]; then printf '%-30s | %-5s |\n' "$name" FAIL; continue; fi
  gcc -O0 -g -I/usr/include "$W/harnessB/memcheck_harness.c" -o "$T/memcheck_harness" "$SO" \
      -Wl,-rpath,"$T/release" 2>"$T/gcc.log" || { printf '%-30s | %-5s | gcc failed\n' "$name" ok; continue; }
  for mode in signcore control ctsub; do
    valgrind -q --error-exitcode=9 "$T/memcheck_harness" "$mode" >"$T/vg-$mode.log" 2>&1; echo $? >"$T/vg-$mode.rc"
  done
  s=$(cat "$T/vg-signcore.rc"); c=$(cat "$T/vg-control.rc"); z=$(cat "$T/vg-ctsub.rc")
  j=$(grep -c "Conditional jump or move depends on uninitialised" "$T/vg-signcore.log")
  a=$(grep -c "Use of uninitialised value" "$T/vg-signcore.log")
  if [ "$c" = 9 ] && [ "$z" = 0 ]; then
    if [ "$s" = 9 ]; then v="leak reported; controls hold"; else v="signcore CLEAN; controls hold"; fi
  else v="VOID: a control did not behave"; fi
  printf '%-30s | %-5s | %-22s | %-7s | %-5s | %s\n' "$name" ok "$s  $j  $a" "$c" "$z" "$v"
done <<'VARIANTS'
o3-thin-default:3:thin:16:
o3-nolto-cgu16:3:off:16:
o2-nolto-cgu16:2:off:16:
o2-thin:2:thin:16:
os-thin:s:thin:16:
oz-thin:z:thin:16:
o3-fat-cgu1:3:fat:1:
o3-thin-native:3:thin:16:-C target-cpu=native
o1-thin:1:thin:16:
VARIANTS
