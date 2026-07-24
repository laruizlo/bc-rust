//! `Limb` — the machine-word building block of `Uint`, with carry-propagating
//! constant-time primitive operations.
//!
//! Width selection is a compile-time property of the target: 64-bit limbs with
//! 128-bit widening arithmetic on 64-bit targets, 32-bit limbs with 64-bit widening
//! elsewhere. The `force_limb32` cfg (registered in `Cargo.toml`) is a test-only
//! escape hatch that exercises the 32-bit path on 64-bit hosts:
//! `RUSTFLAGS="--cfg force_limb32" cargo test -p bouncycastle-rsa`.
//!
//! Officially supported: 64-bit and 32-bit targets. 16-bit targets fall into the
//! `u32` arm; they compile but are not a supported or tested configuration.

use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// The machine word backing a limb.
#[cfg(all(target_pointer_width = "64", not(force_limb32)))]
pub type Word = u64;
/// Double-width word used for widening arithmetic.
#[cfg(all(target_pointer_width = "64", not(force_limb32)))]
pub type WideWord = u128;

/// The machine word backing a limb.
#[cfg(any(not(target_pointer_width = "64"), force_limb32))]
pub type Word = u32;
/// Double-width word used for widening arithmetic.
#[cfg(any(not(target_pointer_width = "64"), force_limb32))]
pub type WideWord = u64;

/// The mask type all constant-time decisions in the bigint engine travel as.
/// `Condition<u64>` and `Condition<u32>` expose identical constructors, so code
/// written against this alias resolves for both limb widths.
pub type Cond = Condition<Word>;

/// Bits per limb (64 or 32).
pub const WORD_BITS: usize = Word::BITS as usize;
/// Bytes per limb (8 or 4).
pub const WORD_BYTES: usize = WORD_BITS / 8;

/// A single limb of a multi-precision unsigned integer.
///
/// Comparisons go through the constant-time predicates only; `PartialEq`/`Ord` are
/// deliberately not derived so there is no accidental variable-time path to reach for.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Limb(pub Word);

impl Limb {
    /// Zero.
    pub const ZERO: Self = Self(0);
    /// One.
    pub const ONE: Self = Self(1);
    /// All bits set.
    pub const MAX: Self = Self(Word::MAX);

    /// Addition with carry: `self + rhs + carry` → `(sum, carry_out)`.
    ///
    /// Carry values are in `{0, 1}`: the carry-out falls out of the wide addition's
    /// high half and chains directly as the next `adc`'s addend. The pair cannot
    /// overflow: `max + max + 1 < B²` for `B = 2^WORD_BITS`.
    #[inline(always)]
    pub const fn adc(self, rhs: Self, carry: Self) -> (Self, Self) {
        let t = self.0 as WideWord + rhs.0 as WideWord + carry.0 as WideWord;
        (Self(t as Word), Self((t >> Word::BITS) as Word))
    }

    /// Subtraction with borrow: `self - rhs - (borrow >> (WORD_BITS-1))` → `(diff, borrow_out)`.
    ///
    /// Borrow values are in `{0, Word::MAX}`: a full mask, normalized on the way in
    /// via its top bit. This asymmetry with [`Self::adc`] is deliberate — the
    /// borrow-out of a wrapping wide subtraction's high half is all-ones exactly when
    /// the subtraction underflowed, so the final borrow of a full chain *is* the `lt`
    /// mask (convertible with `Cond::from_msb`, no post-processing).
    #[inline(always)]
    pub const fn sbb(self, rhs: Self, borrow: Self) -> (Self, Self) {
        let t = (self.0 as WideWord)
            .wrapping_sub(rhs.0 as WideWord + ((borrow.0 >> (Word::BITS - 1)) as WideWord));
        (Self(t as Word), Self((t >> Word::BITS) as Word))
    }

    /// Multiply-accumulate: `self + b·c + carry` → `(low, high)`.
    ///
    /// Cannot overflow the pair: with `B = 2^WORD_BITS`,
    /// `max + max·max + max = (B-1) + (B-1)² + (B-1) = B² - 1 < B²`.
    #[inline(always)]
    pub const fn mac(self, b: Self, c: Self, carry: Self) -> (Self, Self) {
        let t = self.0 as WideWord + (b.0 as WideWord) * (c.0 as WideWord) + carry.0 as WideWord;
        (Self(t as Word), Self((t >> Word::BITS) as Word))
    }

    /// Constant-time: TRUE iff this limb is zero.
    #[inline(always)]
    pub const fn ct_is_zero(self) -> Cond {
        Cond::is_zero(self.0)
    }

    /// Constant-time: TRUE iff `self == rhs`.
    #[inline(always)]
    pub const fn ct_eq(self, rhs: Self) -> Cond {
        Cond::is_equal(self.0, rhs.0)
    }

    /// Constant-time: TRUE iff bit 0 is set (the limb is odd).
    #[inline(always)]
    pub const fn ct_is_odd(self) -> Cond {
        Cond::from_lsb(self.0)
    }
}

impl ZeroizablePrimitive for Limb {
    const ZEROED: Self = Self(0);
}
