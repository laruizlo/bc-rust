//! Tests for `bigint::cmp`: predicate truth tables at boundary values, including
//! off-by-one patterns at every limb boundary, cross-checked against reference
//! (variable-time) comparisons computed in test code.

use crate::bigint::limb::{Limb, WORD_BITS, Word};
use crate::bigint::uint::Uint;

type U4 = Uint<4>;

/// Reference comparison, most-significant limb first. Variable-time is fine in
/// test code; it is the independent oracle the CT versions are checked against.
fn ref_lt(a: &U4, b: &U4) -> bool {
    for i in (0..4).rev() {
        if a.as_limbs()[i].0 != b.as_limbs()[i].0 {
            return a.as_limbs()[i].0 < b.as_limbs()[i].0;
        }
    }
    false
}

fn make(limbs: [Word; 4]) -> U4 {
    let mut u = U4::ZERO;
    for (i, w) in limbs.into_iter().enumerate() {
        u.as_limbs_mut()[i] = Limb(w);
    }
    u
}

/// Boundary values: zero, one, max, max-1, top-bit-only, single-bit-per-limb
/// patterns (B^k), and their predecessors (B^k - 1), which exercise the borrow
/// chain across every limb boundary.
fn boundary_values() -> [U4; 13] {
    let mut vals = [U4::ZERO; 13];
    vals[0] = U4::ZERO;
    vals[1] = U4::ONE;
    vals[2] = U4::MAX;
    vals[3] = make([Word::MAX - 1, Word::MAX, Word::MAX, Word::MAX]); // MAX - 1
    vals[4] = make([0, 0, 0, 1 << (WORD_BITS - 1)]); // top bit only
    // B^k for k = 1..3 and B^k - 1: off-by-one at each limb boundary
    vals[5] = make([0, 1, 0, 0]);
    vals[6] = make([Word::MAX, 0, 0, 0]);
    vals[7] = make([0, 0, 1, 0]);
    vals[8] = make([Word::MAX, Word::MAX, 0, 0]);
    vals[9] = make([0, 0, 0, 1]);
    vals[10] = make([Word::MAX, Word::MAX, Word::MAX, 0]);
    // values differing only in one middle limb
    vals[11] = make([7, 5, 0, 9]);
    vals[12] = make([7, 6, 0, 9]);
    vals
}

#[test]
fn ct_is_zero() {
    assert!(U4::ZERO.ct_is_zero().to_bool());
    for v in boundary_values().iter().skip(1) {
        assert!(!v.ct_is_zero().to_bool());
    }
}

#[test]
fn ct_eq_truth_table() {
    let vals = boundary_values();
    for (i, a) in vals.iter().enumerate() {
        for (j, b) in vals.iter().enumerate() {
            assert_eq!(a.ct_eq(b).to_bool(), i == j);
        }
    }
}

#[test]
fn ct_lt_gt_gte_agree_with_reference() {
    let vals = boundary_values();
    for a in &vals {
        for b in &vals {
            let expected = ref_lt(a, b);
            assert_eq!(a.ct_lt(b).to_bool(), expected);
            assert_eq!(b.ct_gt(a).to_bool(), expected);
            assert_eq!(a.ct_gte(b).to_bool(), !expected);
        }
    }
}

#[test]
fn ct_is_odd() {
    assert!(U4::ONE.ct_is_odd().to_bool());
    assert!(U4::MAX.ct_is_odd().to_bool());
    assert!(!U4::ZERO.ct_is_odd().to_bool());
    // oddness is decided by limb 0 alone
    assert!(!make([0, 1, 1, 1]).ct_is_odd().to_bool());
    assert!(make([1, 0, 0, 0]).ct_is_odd().to_bool());
}

#[test]
fn bit_access() {
    // one bit set per limb: bit k*WORD_BITS + k
    let mut x = U4::ZERO;
    for k in 0..4 {
        x.as_limbs_mut()[k] = Limb(1 << k);
    }
    for i in 0..U4::BITS {
        let expected = (i / WORD_BITS) == (i % WORD_BITS);
        assert_eq!(x.bit(i).to_bool(), expected);
        assert_eq!(x.bit_vartime(i), expected);
    }
    // MAX has every bit set; ZERO none
    for i in 0..U4::BITS {
        assert!(U4::MAX.bit(i).to_bool());
        assert!(!U4::ZERO.bit(i).to_bool());
        assert!(U4::MAX.bit_vartime(i));
        assert!(!U4::ZERO.bit_vartime(i));
    }
}
