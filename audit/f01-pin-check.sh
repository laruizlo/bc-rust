#!/usr/bin/env bash
# claude/rsa-wp14-f01-pin-check.sh
# F-01 at the pin: the second reviewer's leak probe, pointed at upstream's fix.
#
#   rsa-wp14-f01-pin-check.sh <checkout of bcgit/bc-rust at the pin> <work dir>
#
# What it is. The memcheck harness with which the independent reviewer showed F-01 at b7e46cb
# (claude/rsa-f01-review-tree.sh, harnessB), written without sight of the audit's own harness.
# Three changes, each marked CHANGED or ADDED in the files below:
#   1. f01_sign_core builds its context with MontgomeryContext::for_secret_modulus, the constructor
#      the private-key path uses since 04305e0. At b7e46cb it was MontgomeryContext::new.
#   2. f01_public_core is new: the same shape over for_public_modulus, the variable-time constructor.
#      Fed a secret it must still be reported. It is the control on the code: the leak the reviewer
#      found, kept detectable in the very build that is being judged.
#   3. Every limb of the modulus is undefined, the low one included. The reviewer kept limb 0
#      defined so that the old constructor's validity test would not be what got reported; the new
#      one tests nothing about its modulus, so nothing needs sparing (plan 14.4, row F-01 (b)).
#
# What it runs, per build setting, under Valgrind memcheck:
#   signcore  for_secret_modulus -> mod_pow, modulus and base undefined   must be CLEAN
#   pubcore   for_public_modulus -> mod_pow, the same inputs              must be REPORTED
#   control   an explicit branch on the secret (the reviewer's)           must be REPORTED
#   ctsub     the crate's masked sub_mod over the secret (the reviewer's) must be CLEAN
# A variant counts only if its three controls behave; otherwise it is VOID.
# Exit 0 if every variant that could be judged says "fix holds", 1 otherwise.
#
# Scope: the host (x86-64), the toolchain on PATH, RSA-2048's prime width (16 limbs), and a wrapper
# around the real constructor and mod_pow, not crt_exp itself. The audit's own harness covers
# crt_exp, the other sizes and the MSRV (claude/rsa-wp14-report.md, section 4).
# Needs cargo, gcc, Valgrind with its headers. About a minute on two cores.
set -uo pipefail
PIN="$(cd "${1:?usage: rsa-wp14-f01-pin-check.sh <checkout at the pin> <work dir>}" && pwd)"
OUT="${2:?work dir}"; mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
export CARGO_HOME="${CARGO_HOME:-$OUT/.cargo-home}"
H="$OUT/harness"; mkdir -p "$H/src"

cat > "$H/Cargo.toml" <<EOF
[package]
name = "f01_harness_b"
version = "0.0.0"
edition = "2024"
publish = false

[lib]
name = "f01b"
path = "src/lib.rs"
crate-type = ["cdylib"]

[dependencies]
bouncycastle-rsa = { path = "$PIN/crypto/rsa" }

# The workspace's own release profile, as in the checkout's root Cargo.toml.
[profile.release]
lto = "thin"
strip = "debuginfo"

[workspace]
EOF

cat > "$H/src/lib.rs" <<'EOF'
//! F-01 at the pin. The second reviewer's Harness B with one line CHANGED and one function ADDED.
use bouncycastle_rsa::modexp as real;

/// L = 16: the RSA-2048 CRT prime width (the context `crt_exp` builds over `p` and `q`).
/// # Safety: all four pointers are valid `[u64; 16]`.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn f01_sign_core(
    modulus: *const u64,
    base: *const u64,
    exp: *const u64,
    out: *mut u64,
) {
    let modulus = unsafe { &*(modulus as *const [u64; 16]) };
    let base = unsafe { &*(base as *const [u64; 16]) };
    let exp = unsafe { &*(exp as *const [u64; 16]) };
    // CHANGED. At b7e46cb: MontgomeryContext::<16>::new(modulus).expect("odd nonzero modulus").
    let ctx = real::MontgomeryContext::<16>::for_secret_modulus(modulus);
    let result = real::mod_pow::<16, 32, 33>(base, exp, &ctx);
    unsafe { core::ptr::copy_nonoverlapping(result.as_ptr(), out, 16) };
}

/// ADDED. The same shape over the variable-time constructor, which the crate reserves for the
/// public `n`. Fed a secret, it is the leak of F-01 and must be reported.
/// # Safety: all four pointers are valid `[u64; 16]`.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn f01_public_core(
    modulus: *const u64,
    base: *const u64,
    exp: *const u64,
    out: *mut u64,
) {
    let modulus = unsafe { &*(modulus as *const [u64; 16]) };
    let base = unsafe { &*(base as *const [u64; 16]) };
    let exp = unsafe { &*(exp as *const [u64; 16]) };
    let ctx = real::MontgomeryContext::<16>::for_public_modulus(modulus).expect("odd modulus");
    let result = real::mod_pow::<16, 32, 33>(base, exp, &ctx);
    unsafe { core::ptr::copy_nonoverlapping(result.as_ptr(), out, 16) };
}

/// The reviewer's positive control, unchanged: a conditional subtraction written as a data branch
/// on the secret modulus.
/// # Safety: both pointers are valid `[u64; 16]`.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn f01_control_vartime(modulus: *const u64, out: *mut u64) {
    let m = unsafe { &*(modulus as *const [u64; 16]) };
    let mut acc = [0u64; 16];
    acc[0] = 1;
    for _ in 0..(64 * 16) {
        let mut doubled = [0u64; 16];
        let mut carry = 0u64;
        for i in 0..16 {
            let d = (acc[i] << 1) | carry;
            carry = acc[i] >> 63;
            doubled[i] = d;
        }
        let mut borrow = 0u64;
        let mut diff = [0u64; 16];
        for i in 0..16 {
            let (t, b1) = doubled[i].overflowing_sub(m[i]);
            let (t2, b2) = t.overflowing_sub(borrow);
            diff[i] = t2;
            borrow = (b1 as u64) | (b2 as u64);
        }
        if carry == 1 || borrow == 0 {
            acc = diff;
        } else {
            acc = doubled;
        }
    }
    unsafe { core::ptr::copy_nonoverlapping(acc.as_ptr(), out, 16) };
}

/// The reviewer's clean control, unchanged: the crate's own masked `sub_mod` over the same secret.
/// # Safety: all pointers are valid `[u64; 16]`.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn f01_ct_subref(
    a: *const u64,
    b: *const u64,
    modulus: *const u64,
    out: *mut u64,
) {
    let a = unsafe { &*(a as *const [u64; 16]) };
    let b = unsafe { &*(b as *const [u64; 16]) };
    let m = unsafe { &*(modulus as *const [u64; 16]) };
    let r = real::sub_mod::<16>(a, b, m);
    unsafe { core::ptr::copy_nonoverlapping(r.as_ptr(), out, 16) };
}
EOF

cat > "$H/memcheck_harness.c" <<'EOF'
/* F-01 at the pin: the second reviewer's memcheck driver with the taint CHANGED to cover every
 * limb of the modulus, and the mode pubcore ADDED. */
#include <valgrind/memcheck.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern void f01_sign_core(const uint64_t *m, const uint64_t *base, const uint64_t *exp, uint64_t *out);
extern void f01_public_core(const uint64_t *m, const uint64_t *base, const uint64_t *exp, uint64_t *out);
extern void f01_control_vartime(const uint64_t *m, uint64_t *out);
extern void f01_ct_subref(const uint64_t *a, const uint64_t *b, const uint64_t *m, uint64_t *out);

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "signcore";
    uint64_t m[16], base[16], exp[16], a[16], b[16], out[16];

    /* Concrete, valid starting values (odd modulus with both top bits set, base/exp < modulus). */
    for (int i = 0; i < 16; i++) { m[i] = 0x1111111111111111ull * (i + 1); base[i] = i + 1; exp[i] = 7 * i + 3; a[i] = i; b[i] = 2 * i; }
    m[0] |= 1;                       /* odd: the value is, though no bit of it is defined below */
    m[15] |= 0xC000000000000000ull;
    base[15] &= 0x3fffffffffffffffull;
    a[15] &= 0x3fffffffffffffffull; b[15] &= 0x3fffffffffffffffull;

    /* CHANGED: the whole modulus is undefined, limb 0 and its low bit included. */
    VALGRIND_MAKE_MEM_UNDEFINED(m, sizeof m);

    if (strcmp(mode, "signcore") == 0) {
        VALGRIND_MAKE_MEM_UNDEFINED(base, sizeof base);
        f01_sign_core(m, base, exp, out);
    } else if (strcmp(mode, "pubcore") == 0) {          /* ADDED */
        VALGRIND_MAKE_MEM_UNDEFINED(base, sizeof base);
        f01_public_core(m, base, exp, out);
    } else if (strcmp(mode, "control") == 0) {
        f01_control_vartime(m, out);
    } else if (strcmp(mode, "ctsub") == 0) {
        VALGRIND_MAKE_MEM_UNDEFINED(a, sizeof a);
        VALGRIND_MAKE_MEM_UNDEFINED(b, sizeof b);
        f01_ct_subref(a, b, m, out);
    } else {
        fprintf(stderr, "usage: %s signcore|pubcore|control|ctsub\n", argv[0]);
        return 2;
    }
    /* Make the result defined so printing it is not itself a report. */
    VALGRIND_MAKE_MEM_DEFINED(out, sizeof out);
    uint64_t acc = 0;
    for (int i = 0; i < 16; i++) acc ^= out[i];
    printf("%s done (digest %016llx)\n", mode, (unsigned long long)acc);
    return 0;
}
EOF

echo "pin: $(git -C "$PIN" rev-parse HEAD 2>/dev/null || echo 'not a git checkout')"
rustc --version; valgrind --version
printf '%-16s | %-8s | %-18s | %-7s | %-5s | %s\n' variant signcore "pubcore (jump addr)" control ctsub verdict
bad=0; judged=0
# name : opt-level : lto : codegen-units : RUSTFLAGS
while IFS=: read -r name opt lto cgu flags; do
  [ -z "$name" ] && continue
  T="$OUT/$name"; mkdir -p "$T"
  ( cd "$H" && CARGO_TARGET_DIR="$T" CARGO_PROFILE_RELEASE_OPT_LEVEL="$opt" \
      CARGO_PROFILE_RELEASE_LTO="$lto" CARGO_PROFILE_RELEASE_CODEGEN_UNITS="$cgu" RUSTFLAGS="$flags" \
      cargo build --release --quiet ) >"$T/build.log" 2>&1
  SO="$T/release/libf01b.so"
  if [ ! -f "$SO" ]; then printf '%-16s | build failed, see %s\n' "$name" "$T/build.log"; bad=1; continue; fi
  if ! gcc -O0 -g "$H/memcheck_harness.c" -o "$T/memcheck_harness" "$SO" -Wl,-rpath,"$T/release" 2>"$T/gcc.log"; then
    printf '%-16s | gcc failed, see %s\n' "$name" "$T/gcc.log"; bad=1; continue
  fi
  for mode in signcore pubcore control ctsub; do
    valgrind -q --error-exitcode=9 "$T/memcheck_harness" "$mode" >"$T/vg-$mode.log" 2>&1; echo $? >"$T/vg-$mode.rc"
  done 2>/dev/null
  s=$(cat "$T/vg-signcore.rc"); p=$(cat "$T/vg-pubcore.rc"); c=$(cat "$T/vg-control.rc"); z=$(cat "$T/vg-ctsub.rc")
  j=$(grep -c "Conditional jump or move depends on uninitialised" "$T/vg-pubcore.log")
  a=$(grep -c "Use of uninitialised value" "$T/vg-pubcore.log")
  w() { case "$1" in 0) echo clean;; 9) echo REPORTED;; *) echo "rc=$1";; esac; }
  if [ "$p" = 9 ] && [ "$c" = 9 ] && [ "$z" = 0 ]; then
    judged=$((judged+1))
    if [ "$s" = 0 ]; then v="fix holds"; else v="LEAK: signcore reported"; bad=1; fi
  else v="VOID: a control did not behave"; fi
  printf '%-16s | %-8s | %-18s | %-7s | %-5s | %s\n' "$name" "$(w "$s")" "$(w "$p") ($j $a)" "$(w "$c")" "$(w "$z")" "$v"
done <<'VARIANTS'
o3-thin-default:3:thin:16:
o3-nolto-cgu16:3:off:16:
o2-nolto-cgu16:2:off:16:
o2-thin:2:thin:16:
os-thin:s:thin:16:
oz-thin:z:thin:16:
o3-fat-cgu1:3:fat:1:
o1-thin:1:thin:16:
o3-thin-native:3:thin:16:-C target-cpu=native
VARIANTS
echo "judged: $judged of 9 variants"
if [ "$bad" = 0 ] && [ "$judged" -gt 0 ]; then echo "F-01 PIN CHECK: fix holds in every variant judged"; exit 0; fi
echo "F-01 PIN CHECK: NOT as expected"; exit 1
