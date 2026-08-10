//! Constant-time predicates over `Uint<LIMBS>`.
//!
//! Every function here is fixed-iteration over `LIMBS`, mask-based, and free of
//! secret-dependent branches or indices. Each returns `Cond` (`Condition<Word>`),
//! never `bool`; callers convert with `to_bool` only at public decision points.

use super::limb::{Cond, Limb, WORD_BITS, Word};
use super::uint::Uint;

impl<const LIMBS: usize> Uint<LIMBS> {
    /// TRUE iff `self == 0`. OR-fold of all limbs, single zero test on the
    /// accumulator.
    pub fn ct_is_zero(&self) -> Cond {
        let mut acc: Word = 0;
        for i in 0..LIMBS {
            acc |= core::hint::black_box(self.as_limbs()[i].0);
        }
        Cond::is_zero(acc)
    }

    /// TRUE iff `self == rhs`. XOR-difference OR-fold, zero test. This is the
    /// primary internal equality; the `PartialEq` impl is a convenience over the
    /// same fold shape.
    pub fn ct_eq(&self, rhs: &Self) -> Cond {
        let mut acc: Word = 0;
        for i in 0..LIMBS {
            acc |= core::hint::black_box(self.as_limbs()[i].0 ^ rhs.as_limbs()[i].0);
        }
        Cond::is_zero(acc)
    }

    /// TRUE iff `self < rhs`. Full `sbb` chain; the final borrow mask is the
    /// result (the limb layer's borrow convention), converted via `from_msb`
    /// with no post-processing.
    pub fn ct_lt(&self, rhs: &Self) -> Cond {
        let mut borrow = Limb::ZERO;
        for i in 0..LIMBS {
            let (_, b) = self.as_limbs()[i].sbb(rhs.as_limbs()[i], borrow);
            borrow = b;
        }
        Cond::from_msb(borrow.0)
    }

    /// TRUE iff `self > rhs`.
    pub fn ct_gt(&self, rhs: &Self) -> Cond {
        rhs.ct_lt(self)
    }

    /// TRUE iff `self >= rhs`.
    pub fn ct_gte(&self, rhs: &Self) -> Cond {
        !self.ct_lt(rhs)
    }

    /// TRUE iff `self` is odd. Mask from `limbs[0] & 1`; this is the "modulus
    /// must be odd" gate for the Montgomery machinery in phase 3.
    pub fn ct_is_odd(&self) -> Cond {
        self.as_limbs()[0].ct_is_odd()
    }

    /// Bit at position `i`: constant-time in the *value*, public in the *index*.
    ///
    /// Phase 3 scans secret exponent bits at public positions, which is exactly
    /// this shape: the returned mask hides the bit's value, while `i` itself is
    /// loop-counter data. Requires `i < Self::BITS`; the index arithmetic is on
    /// public quantities only.
    pub fn bit(&self, i: usize) -> Cond {
        Cond::from_lsb(self.as_limbs()[i / WORD_BITS].0 >> (i % WORD_BITS))
    }

    /// Bit at position `i`, variable-time. `_vartime` per the module naming rule:
    /// the shift amount and any caller branching on the returned `bool` are
    /// timing-visible, so inputs must be public values (e.g. scanning a public
    /// exponent). For secret values use [`Self::bit`].
    pub fn bit_vartime(&self, i: usize) -> bool {
        (self.as_limbs()[i / WORD_BITS].0 >> (i % WORD_BITS)) & 1 == 1
    }
}
