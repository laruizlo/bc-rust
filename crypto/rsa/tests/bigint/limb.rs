//! Tests for `bigint::limb`: carry/borrow/mac identities and word-level predicates.

use crate::bigint::limb::{Cond, Limb, WORD_BITS, WORD_BYTES, WideWord, Word};
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// Boundary words: the values where carry/borrow/widening bugs live.
const BOUNDARY: [Word; 5] = [0, 1, Word::MAX, Word::MAX - 1, 1 << (WORD_BITS - 1)];

#[test]
fn word_width_matches_target() {
    #[cfg(all(target_pointer_width = "64", not(force_limb32)))]
    assert_eq!(WORD_BITS, 64);
    #[cfg(any(not(target_pointer_width = "64"), force_limb32))]
    assert_eq!(WORD_BITS, 32);
    assert_eq!(WORD_BYTES * 8, WORD_BITS);
}

#[test]
fn adc_identities() {
    // max + 1 wraps to (0, carry 1)
    let (s, c) = Limb::MAX.adc(Limb::ONE, Limb::ZERO);
    assert!(s.0 == 0 && c.0 == 1);
    // max + max + 1 = (max, carry 1): the largest chainable inputs stay in range
    let (s, c) = Limb::MAX.adc(Limb::MAX, Limb::ONE);
    assert!(s.0 == Word::MAX && c.0 == 1);
    // carry-out is always 0 or 1 across boundary pairs, and matches wide arithmetic
    for a in BOUNDARY {
        for b in BOUNDARY {
            for carry in [0, 1] {
                let (s, c) = Limb(a).adc(Limb(b), Limb(carry));
                let wide = a as WideWord + b as WideWord + carry as WideWord;
                assert_eq!(s.0, wide as Word);
                assert_eq!(c.0, (wide >> WORD_BITS) as Word);
                assert!(c.0 <= 1);
            }
        }
    }
}

#[test]
fn sbb_identities() {
    // 0 - 1 underflows: diff wraps to max, borrow-out is a FULL MASK (not 1)
    let (d, b) = Limb::ZERO.sbb(Limb::ONE, Limb::ZERO);
    assert!(d.0 == Word::MAX && b.0 == Word::MAX);
    // no underflow -> borrow-out 0
    let (d, b) = Limb::ONE.sbb(Limb::ONE, Limb::ZERO);
    assert!(d.0 == 0 && b.0 == 0);
    // borrow-in is normalized from the top bit: a full-mask borrow subtracts exactly 1
    let (d, b) = Limb::ONE.sbb(Limb::ZERO, Limb::MAX);
    assert!(d.0 == 0 && b.0 == 0);
    // borrow-out is always 0 or MAX across boundary pairs, and matches wide arithmetic
    for a in BOUNDARY {
        for x in BOUNDARY {
            for borrow in [0, Word::MAX] {
                let (d, bo) = Limb(a).sbb(Limb(x), Limb(borrow));
                let wide = (a as WideWord)
                    .wrapping_sub(x as WideWord + ((borrow >> (WORD_BITS - 1)) as WideWord));
                assert_eq!(d.0, wide as Word);
                assert_eq!(bo.0, (wide >> WORD_BITS) as Word);
                assert!(bo.0 == 0 || bo.0 == Word::MAX);
            }
        }
    }
}

#[test]
fn sbb_borrow_is_lt_mask() {
    // The convention the whole engine relies on (spec §3.2): a single-limb borrow-out
    // converts straight to the lt mask via from_msb.
    for a in BOUNDARY {
        for b in BOUNDARY {
            let (_, borrow) = Limb(a).sbb(Limb(b), Limb::ZERO);
            assert_eq!(Cond::from_msb(borrow.0).to_bool(), a < b);
        }
    }
}

#[test]
fn mac_identities() {
    // max·max = (max-1)·B + 1: the classic no-overflow-of-the-pair identity
    let (lo, hi) = Limb::ZERO.mac(Limb::MAX, Limb::MAX, Limb::ZERO);
    assert!(lo.0 == 1 && hi.0 == Word::MAX - 1);
    // saturating the accumulate inputs still cannot overflow the pair:
    // max + max·max + max = B² - 1 = (max, max)
    let (lo, hi) = Limb::MAX.mac(Limb::MAX, Limb::MAX, Limb::MAX);
    assert!(lo.0 == Word::MAX && hi.0 == Word::MAX);
    // cross-check against wide arithmetic on boundary triples
    for a in BOUNDARY {
        for b in BOUNDARY {
            for c in BOUNDARY {
                let (lo, hi) = Limb(a).mac(Limb(b), Limb(c), Limb::ZERO);
                let wide = a as WideWord + (b as WideWord) * (c as WideWord);
                assert_eq!(lo.0, wide as Word);
                assert_eq!(hi.0, (wide >> WORD_BITS) as Word);
            }
        }
    }
}

#[test]
fn ct_predicates() {
    assert!(Limb::ZERO.ct_is_zero().to_bool());
    assert!(!Limb::ONE.ct_is_zero().to_bool());
    assert!(!Limb::MAX.ct_is_zero().to_bool());

    assert!(Limb::MAX.ct_eq(Limb::MAX).to_bool());
    assert!(!Limb::MAX.ct_eq(Limb(Word::MAX - 1)).to_bool());

    assert!(Limb::ONE.ct_is_odd().to_bool());
    assert!(Limb::MAX.ct_is_odd().to_bool());
    assert!(!Limb::ZERO.ct_is_odd().to_bool());
    assert!(!Limb(Word::MAX - 1).ct_is_odd().to_bool());
}

#[test]
fn zeroizable() {
    assert_eq!(Limb::ZEROED.0, 0);
}
