//! Finding F-01, second review — Harness B (binary inspection).
//!
//! `f01_sign_core` reproduces exactly what `rsa_core::crt_exp` does per secret prime: build the
//! Montgomery context over the (secret) modulus, then `mod_pow` over it. It calls the REAL
//! snapshot code (`bouncycastle_rsa::modexp`), so disassembling this symbol in a release build
//! made with the workspace's own `[profile.release]` shows the actual machine code the audited
//! `MontgomeryContext::new` -> `pow2_mod` -> `double_mod_n` is lowered to.
//!
//! `mod_pow` reads `ctx.r_mod_n` and (through `to_montgomery`) `ctx.r2_mod_n`, so neither
//! `pow2_mod(64L)` nor `pow2_mod(128L)` can be optimised away: both doubling loops are live.

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
    // Exactly crt_exp's shape: MontgomeryContext::<HALF>::new(prime) then mod_pow over it.
    let ctx = real::MontgomeryContext::<16>::new(modulus).expect("odd nonzero modulus");
    let result = real::mod_pow::<16, 32, 33>(base, exp, &ctx);
    unsafe { core::ptr::copy_nonoverlapping(result.as_ptr(), out, 16) };
}

/// A deliberately variable-time positive control: a conditional subtraction written as a data
/// branch on the secret modulus, the archetype of what `double_mod_n` does. If the build pipeline
/// somehow rendered everything branchless, THIS must still show a secret-dependent branch, so a
/// clean result on `f01_sign_core` would be meaningful rather than a tooling artefact.
/// # Safety: both pointers are valid `[u64; 16]`.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn f01_control_vartime(modulus: *const u64, out: *mut u64) {
    let m = unsafe { &*(modulus as *const [u64; 16]) };
    let mut acc = [0u64; 16];
    acc[0] = 1;
    // One doubling-and-conditional-subtract, branching on the secret exactly as the source `if`
    // in double_mod_n does, but with no barrier at all.
    for _ in 0..(64 * 16) {
        let mut doubled = [0u64; 16];
        let mut carry = 0u64;
        for i in 0..16 {
            let d = (acc[i] << 1) | carry;
            carry = acc[i] >> 63;
            doubled[i] = d;
        }
        // borrow = doubled < m ?
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

/// Clean control: the crate's OWN branch-free modular subtract `sub_mod` (RFC 8017 CRT step,
/// documented "constant time with respect to `modulus`", modexp.rs:174) over the same secret
/// modulus. It uses `ct_select_array` -> `Condition::select` with the volatile barrier, so it must
/// stay CLEAN under memcheck where `f01_sign_core` and `f01_control_vartime` do not — demonstrating
/// that memcheck is not simply always-firing, and that the leak is specific to `double_mod_n`'s
/// plain `if`, not to doing a conditional modular reduction over a secret at all.
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
