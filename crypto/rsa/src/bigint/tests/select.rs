//! Tests for `bigint::select`: conditional select / assign / swap.

use crate::bigint::limb::{Cond, Limb, Word};
use crate::bigint::uint::Uint;

type U4 = Uint<4>;

/// Distinct bit patterns per limb so any wrong-limb or wrong-mask bug shows.
fn patterned(seed: u64) -> U4 {
    let mut u = U4::ZERO;
    for i in 0..4 {
        let w = seed.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64 * 0x0101_0101);
        u.as_limbs_mut()[i] = Limb(w as Word);
    }
    u
}

#[test]
fn select_picks_by_condition() {
    let a = patterned(1);
    let b = patterned(2);
    assert!(U4::select(Cond::TRUE, &a, &b) == a);
    assert!(U4::select(Cond::FALSE, &a, &b) == b);
}

#[test]
fn conditional_assign() {
    let src = patterned(3);
    let mut dst = patterned(4);
    dst.conditional_assign(&src, Cond::FALSE);
    assert!(dst == patterned(4));
    dst.conditional_assign(&src, Cond::TRUE);
    assert!(dst == src);
}

#[test]
fn conditional_swap() {
    let a0 = patterned(5);
    let b0 = patterned(6);

    let (mut a, mut b) = (a0, b0);
    U4::conditional_swap(&mut a, &mut b, Cond::FALSE);
    assert!(a == a0 && b == b0);

    U4::conditional_swap(&mut a, &mut b, Cond::TRUE);
    assert!(a == b0 && b == a0);

    // swap twice under TRUE is the identity
    U4::conditional_swap(&mut a, &mut b, Cond::TRUE);
    assert!(a == a0 && b == b0);
}
