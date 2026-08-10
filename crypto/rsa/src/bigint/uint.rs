//! `Uint<LIMBS>`: stack-only, fixed-precision unsigned integer storage.
//!
//! This is the storage layer only: consts, accessors, equality, and the capacity
//! aliases. Predicates and conditional operations live in `cmp`/`select`; arithmetic
//! arrives in phase 2.

use super::limb::{Limb, WORD_BITS, WORD_BYTES, Word};
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// Fixed-precision unsigned integer. Little-endian limb order: `limbs[0]` is least
/// significant. Big-endian byte order appears only at the encoding boundary.
///
/// The precision is the type: a value occupies all `LIMBS` limbs at all times and
/// every operation loops `0..LIMBS` unconditionally, so timing depends on capacity
/// (public, type-level) and never on the value held. There is no runtime length field
/// by design: data-dependent effective lengths are exactly what constant-time code
/// must not have, and capacity-as-type turns length mismatches into compile errors.
///
/// `Uint` is not inherently secret (same stance as `mldsa::Polynomial`): public
/// values (modulus, public exponent, blinded intermediates) live as bare `Uint`;
/// anything secret must be born inside `Secret<Uint<N>>` and populated in place.
/// Do not let secret material sit in bare `Uint` temporaries.
#[derive(Clone, Copy)]
pub struct Uint<const LIMBS: usize> {
    limbs: [Limb; LIMBS],
}

impl<const LIMBS: usize> Uint<LIMBS> {
    /// Total bits of capacity. (Follows `u64::BITS` naming for numeric types; the
    /// house `_SIZE`/`_LEN` convention applies to the RSA-level constants that later
    /// phases derive from these.)
    pub const BITS: usize = LIMBS * WORD_BITS;
    /// Total bytes of capacity.
    pub const BYTES: usize = LIMBS * WORD_BYTES;
    /// Zero.
    pub const ZERO: Self = Self { limbs: [Limb::ZERO; LIMBS] };
    /// One. Requires `LIMBS >= 1`; a `Uint<0>` use of this const fails to compile
    /// at monomorphization (no zero-limb integer holds the value 1).
    pub const ONE: Self = {
        let mut limbs = [Limb::ZERO; LIMBS];
        limbs[0] = Limb::ONE;
        Self { limbs }
    };
    /// All bits set.
    pub const MAX: Self = Self { limbs: [Limb::MAX; LIMBS] };

    /// Borrow the limbs, least significant first.
    #[inline(always)]
    pub const fn as_limbs(&self) -> &[Limb; LIMBS] {
        &self.limbs
    }

    /// Mutably borrow the limbs, least significant first.
    #[inline(always)]
    pub const fn as_limbs_mut(&mut self) -> &mut [Limb; LIMBS] {
        &mut self.limbs
    }
}

impl<const LIMBS: usize> ZeroizablePrimitive for Uint<LIMBS> {
    const ZEROED: Self = Self::ZERO;
}

/// Constant-time equality: a non-short-circuiting XOR-difference fold over every
/// limb with a single zero test on the accumulator. Never derived, because derived
/// array `==` short-circuits on the first differing limb and leaks the position of
/// the difference through timing.
///
/// The mask-returning `ct_eq` in `cmp` is the primary internal form; this impl is
/// the `bool` convenience over it for public decision points and tests.
impl<const LIMBS: usize> PartialEq for Uint<LIMBS> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).to_bool()
    }
}
impl<const LIMBS: usize> Eq for Uint<LIMBS> {}

/// Hex limb dump, most-significant limb first, which is legitimate for the public
/// values bare `Uint`s hold. Secret instances sit inside `Secret<...>`, whose
/// redacting `Debug` takes precedence regardless of this impl.
impl<const LIMBS: usize> core::fmt::Debug for Uint<LIMBS> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Uint<{}>(0x", LIMBS)?;
        // Print most significant limb first to match conventional hex notation;
        // limbs are stored little-endian.
        for i in (0..LIMBS).rev() {
            write!(f, "{:0width$x}", self.limbs[i].0, width = WORD_BYTES * 2)?;
        }
        f.write_str(")")
    }
}

// --- Capacity aliases (spec section 3.4) ---
//
// Bit sizes are width-independent: the same alias means the same number of bits on
// every target, only the limb count behind it changes. All named sizes are multiples
// of 64, so the division is exact under both limb widths.

/// 1024-bit capacity (CRT half of RSA-2048).
pub type U1024 = Uint<{ 1024 / WORD_BITS }>;
/// 1536-bit capacity (CRT half of RSA-3072).
pub type U1536 = Uint<{ 1536 / WORD_BITS }>;
/// 2048-bit capacity.
pub type U2048 = Uint<{ 2048 / WORD_BITS }>;
/// 3072-bit capacity.
pub type U3072 = Uint<{ 3072 / WORD_BITS }>;
/// 4096-bit capacity (also the CRT half of RSA-8192).
pub type U4096 = Uint<{ 4096 / WORD_BITS }>;
/// 6144-bit capacity (3072-bit products).
pub type U6144 = Uint<{ 6144 / WORD_BITS }>;
/// 8192-bit capacity.
pub type U8192 = Uint<{ 8192 / WORD_BITS }>;
/// 16384-bit capacity (8192-bit products).
pub type U16384 = Uint<{ 16384 / WORD_BITS }>;
