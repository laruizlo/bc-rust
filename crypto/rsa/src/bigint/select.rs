//! Conditional select / assign / swap over `Uint<LIMBS>`.
//!
//! These are the primitives phase 3's ladder and masked-table-scan code consumes.
//! All are fixed-iteration per-limb mask operations; the condition mask decides,
//! never a branch.

use super::limb::{Cond, Limb};
use super::uint::Uint;

impl<const LIMBS: usize> Uint<LIMBS> {
    /// Return `a` if `cond` is TRUE, else `b`. Per-limb `Cond::select`.
    pub fn select(cond: Cond, a: &Self, b: &Self) -> Self {
        let mut out = Self::ZERO;
        for i in 0..LIMBS {
            out.as_limbs_mut()[i] = Limb(cond.select(a.as_limbs()[i].0, b.as_limbs()[i].0));
        }
        out
    }

    /// Overwrite `self` with `src` where `cond` is TRUE; otherwise leave `self`
    /// unchanged. Per-limb `Cond::mov`.
    pub fn conditional_assign(&mut self, src: &Self, cond: Cond) {
        for i in 0..LIMBS {
            cond.mov(src.as_limbs()[i].0, &mut self.as_limbs_mut()[i].0);
        }
    }

    /// Swap `a` and `b` where `cond` is TRUE; otherwise leave both unchanged.
    /// Per-limb `Cond::swap` (the XOR-mask trick).
    pub fn conditional_swap(a: &mut Self, b: &mut Self, cond: Cond) {
        for i in 0..LIMBS {
            let (x, y) = cond.swap(a.as_limbs()[i].0, b.as_limbs()[i].0);
            a.as_limbs_mut()[i] = Limb(x);
            b.as_limbs_mut()[i] = Limb(y);
        }
    }
}
