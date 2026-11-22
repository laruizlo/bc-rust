//! Instrumented copy of the Montgomery-context construction from
//! `crypto/rsa/src/modexp.rs` of the snapshot.
//!
//! Every function below is TEXTUALLY the snapshot's (see modexp.rs line cited over each), with
//! ONE addition: `double_mod_n` calls `record_branch(b)` with the value its `if` selects on. The
//! recorder is the whole instrumentation; nothing else is changed. `run_all.sh` prints a diff that
//! shows only the recorder lines added. Faithfulness is additionally cross-checked at run time
//! against the real crate's public `mod_pow` / `mont_n_prime` (see main.rs).

use bouncycastle_ec::montgomery;
use bouncycastle_ec::nat;
use bouncycastle_utils::ct::Condition;

use core::cell::RefCell;

thread_local! {
    static BRANCHES: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static RECORDING: RefCell<bool> = const { RefCell::new(false) };
}

/// Instrumentation only: start/stop recording and drain the recorded branch decisions.
pub fn record_start() {
    BRANCHES.with(|b| b.borrow_mut().clear());
    RECORDING.with(|r| *r.borrow_mut() = true);
}
pub fn record_take() -> Vec<u8> {
    RECORDING.with(|r| *r.borrow_mut() = false);
    BRANCHES.with(|b| b.borrow_mut().clone())
}
#[inline(always)]
fn record_branch(b: u8) {
    if RECORDING.with(|r| *r.borrow()) {
        BRANCHES.with(|v| v.borrow_mut().push(b));
    }
}

// modexp.rs:44-51 (verbatim)
pub fn mont_n_prime(n0: u64) -> u64 {
    debug_assert_eq!(n0 & 1, 1, "mont_n_prime needs an odd modulus");
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

// modexp.rs:56-60 (verbatim) + the single recorder call.
fn double_mod_n<const L: usize>(a: &[u64; L], n: &[u64; L]) -> [u64; L] {
    let (doubled, carry) = nat::add(a, a);
    let (diff, borrow) = nat::sub(&doubled, n);
    record_branch(if carry == 1 || borrow == 0 { 1 } else { 0 }); // <-- instrumentation ONLY
    if carry == 1 || borrow == 0 { diff } else { doubled }
}

// modexp.rs:64-71 (verbatim)
fn pow2_mod<const L: usize>(bits: u32, n: &[u64; L]) -> [u64; L] {
    let mut acc = [0u64; L];
    acc[0] = 1;
    for _ in 0..bits {
        acc = double_mod_n(&acc, n);
    }
    acc
}

// modexp.rs:74-80 (verbatim)
fn ct_select_array<const L: usize>(mask: Condition<u64>, a: &[u64; L], b: &[u64; L]) -> [u64; L] {
    let mut result = [0u64; L];
    for i in 0..L {
        result[i] = mask.select(a[i], b[i]);
    }
    result
}

// modexp.rs:83-89 (verbatim)
fn ct_swap_array<const L: usize>(mask: Condition<u64>, a: &mut [u64; L], b: &mut [u64; L]) {
    for i in 0..L {
        let (x, y) = mask.swap(a[i], b[i]);
        a[i] = x;
        b[i] = y;
    }
}

// modexp.rs:99-112 (verbatim)
fn redc_normalize<const L: usize, const L2: usize, const L21: usize>(
    t: &[u64; L2],
    modulus: &[u64; L],
    n_prime: u64,
) -> [u64; L] {
    let (high, extra) = montgomery::redc::<L, L2, L21>(t, modulus, n_prime);
    let (diff, borrow) = nat::sub(&high, modulus);
    let subtract = Condition::<u64>::from_lsb(extra) | Condition::<u64>::from_lsb(borrow ^ 1);
    ct_select_array(subtract, &diff, &high)
}

// modexp.rs:114-122 (verbatim)
fn mont_mul<const L: usize, const L2: usize, const L21: usize>(
    a: &[u64; L],
    b: &[u64; L],
    modulus: &[u64; L],
    n_prime: u64,
) -> [u64; L] {
    let t = montgomery::widening_mul::<L, L2>(a, b);
    redc_normalize::<L, L2, L21>(&t, modulus, n_prime)
}

// modexp.rs:124-131 (verbatim)
fn mont_square<const L: usize, const L2: usize, const L21: usize>(
    a: &[u64; L],
    modulus: &[u64; L],
    n_prime: u64,
) -> [u64; L] {
    let t = montgomery::widening_square::<L, L2>(a);
    redc_normalize::<L, L2, L21>(&t, modulus, n_prime)
}

// modexp.rs:133-139 (verbatim)
fn to_montgomery<const L: usize, const L2: usize, const L21: usize>(
    a: &[u64; L],
    ctx: &MontgomeryContext<L>,
) -> [u64; L] {
    let t = montgomery::widening_mul::<L, L2>(a, &ctx.r2_mod_n);
    redc_normalize::<L, L2, L21>(&t, &ctx.modulus, ctx.n_prime)
}

// modexp.rs:141-150 (verbatim, minus the zeroize of a scratch local that does not affect output)
fn from_montgomery<const L: usize, const L2: usize, const L21: usize>(
    a_bar: &[u64; L],
    ctx: &MontgomeryContext<L>,
) -> [u64; L] {
    let mut padded = [0u64; L2];
    padded[..L].copy_from_slice(a_bar);
    redc_normalize::<L, L2, L21>(&padded, &ctx.modulus, ctx.n_prime)
}

// modexp.rs:235-266 (struct + new, verbatim; derived ZeroizablePrimitive impl omitted — unused here)
#[derive(Clone, Copy)]
pub struct MontgomeryContext<const L: usize> {
    modulus: [u64; L],
    n_prime: u64,
    #[allow(dead_code)]
    r_mod_n: [u64; L],
    r2_mod_n: [u64; L],
}

impl<const L: usize> MontgomeryContext<L> {
    pub fn new(modulus: &[u64; L]) -> Option<Self> {
        if modulus[0] & 1 == 0 || nat::is_zero(modulus).to_bool() {
            return None;
        }
        let n_prime = mont_n_prime(modulus[0]);
        let r_mod_n = pow2_mod(64 * L as u32, modulus);
        let r2_mod_n = pow2_mod(128 * L as u32, modulus);
        Some(Self { modulus: *modulus, n_prime, r_mod_n, r2_mod_n })
    }
}

// modexp.rs:274-308 (verbatim, minus the final zeroize scrubs that do not affect the return value)
pub fn mod_pow<const L: usize, const L2: usize, const L21: usize>(
    base: &[u64; L],
    exponent: &[u64; L],
    ctx: &MontgomeryContext<L>,
) -> [u64; L] {
    debug_assert_eq!(nat::sub(base, &ctx.modulus).1, 1, "mod_pow needs base < modulus");

    let mut r0 = ctx.r_mod_n;
    let mut r1 = to_montgomery::<L, L2, L21>(base, ctx);
    let mut new_r0 = [0u64; L];
    let mut new_r1 = [0u64; L];

    for limb_index in (0..L).rev() {
        for bit_index in (0..64u32).rev() {
            let mask = Condition::<u64>::is_bit_set(exponent[limb_index], bit_index);
            ct_swap_array(mask, &mut r0, &mut r1);
            new_r1 = mont_mul::<L, L2, L21>(&r0, &r1, &ctx.modulus, ctx.n_prime);
            new_r0 = mont_square::<L, L2, L21>(&r0, &ctx.modulus, ctx.n_prime);
            r0 = new_r0;
            r1 = new_r1;
            ct_swap_array(mask, &mut r0, &mut r1);
        }
    }

    from_montgomery::<L, L2, L21>(&r0, ctx)
}
