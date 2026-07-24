//! Byte encoding and decoding for `Uint<LIMBS>`.
//!
//! RFC 8017 section 4 defines the integer/octet-string conversions RSA uses on the
//! wire: I2OSP (section 4.1, integer to big-endian octet string of a fixed length,
//! error if the integer does not fit) and OS2IP (section 4.2, big-endian octet
//! string to integer). The exact-size array forms below make the length relation a
//! compile-time property, so the "does not fit" error class of I2OSP cannot occur;
//! the one fallible entry point is the ragged-slice import, where the length is
//! caller-controlled input.

use super::limb::{Limb, WORD_BYTES, Word};
use super::uint::Uint;

/// Error for the ragged-slice import path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input is longer than the target capacity in bytes. Carries
    /// `(input_len, capacity_len)` for diagnostics; both are public quantities.
    InputTooLong(usize, usize),
}

impl<const LIMBS: usize> Uint<LIMBS> {
    /// OS2IP (RFC 8017 section 4.2) for exactly capacity-sized input: interpret
    /// `bytes` as a big-endian unsigned integer.
    ///
    /// The length relation is enforced at compile time: `N` must equal
    /// `LIMBS * WORD_BYTES` or the program does not build. Constant-time in the
    /// byte values; the length is a type-level constant.
    pub const fn from_be_bytes<const N: usize>(bytes: &[u8; N]) -> Self {
        const {
            assert!(N == LIMBS * WORD_BYTES, "byte length must equal Uint capacity");
        }
        let mut out = Self::ZERO;
        // OS2IP step 1: x = sum over i of x_i * 256^(xLen - 1 - i).
        // bytes[N-1] is the least significant byte; limbs[0] the least significant limb.
        let mut i = 0;
        while i < LIMBS {
            let mut w: Word = 0;
            let mut j = 0;
            while j < WORD_BYTES {
                w = (w << 8) | bytes[N - (i + 1) * WORD_BYTES + j] as Word;
                j += 1;
            }
            out.as_limbs_mut()[i] = Limb(w);
            i += 1;
        }
        out
    }

    /// I2OSP (RFC 8017 section 4.1) at exactly capacity size: encode as a
    /// big-endian octet string of `N = LIMBS * WORD_BYTES` bytes.
    ///
    /// I2OSP step 1 ("if x >= 256^xLen, output error") cannot occur here: the
    /// value is bounded by the capacity, and `N` equals the capacity at compile
    /// time. Constant-time in the value.
    pub const fn to_be_bytes<const N: usize>(&self) -> [u8; N] {
        const {
            assert!(N == LIMBS * WORD_BYTES, "byte length must equal Uint capacity");
        }
        let mut out = [0u8; N];
        // I2OSP step 2: write the base-256 digits most significant first.
        let mut i = 0;
        while i < LIMBS {
            let w = self.as_limbs()[i].0;
            let mut j = 0;
            while j < WORD_BYTES {
                out[N - 1 - i * WORD_BYTES - j] = (w >> (8 * j)) as u8;
                j += 1;
            }
            i += 1;
        }
        out
    }

    /// Little-endian variant of [`Self::from_be_bytes`]. Not an RFC 8017 wire
    /// format; provided for test-vector ergonomics.
    pub const fn from_le_bytes<const N: usize>(bytes: &[u8; N]) -> Self {
        const {
            assert!(N == LIMBS * WORD_BYTES, "byte length must equal Uint capacity");
        }
        let mut out = Self::ZERO;
        let mut i = 0;
        while i < LIMBS {
            let mut w: Word = 0;
            let mut j = 0;
            while j < WORD_BYTES {
                w |= (bytes[i * WORD_BYTES + j] as Word) << (8 * j);
                j += 1;
            }
            out.as_limbs_mut()[i] = Limb(w);
            i += 1;
        }
        out
    }

    /// Little-endian variant of [`Self::to_be_bytes`]. Not an RFC 8017 wire
    /// format; provided for test-vector ergonomics.
    pub const fn to_le_bytes<const N: usize>(&self) -> [u8; N] {
        const {
            assert!(N == LIMBS * WORD_BYTES, "byte length must equal Uint capacity");
        }
        let mut out = [0u8; N];
        let mut i = 0;
        while i < LIMBS {
            let w = self.as_limbs()[i].0;
            let mut j = 0;
            while j < WORD_BYTES {
                out[i * WORD_BYTES + j] = (w >> (8 * j)) as u8;
                j += 1;
            }
            i += 1;
        }
        out
    }

    /// In-place big-endian decode, for populating `Secret`-owned storage through
    /// `DerefMut` with no by-value return of the decoded material:
    ///
    /// ```text
    /// let mut d: Secret<U2048> = Secret::new();
    /// U2048::decode_be_into(&bytes, &mut d);
    /// ```
    pub fn decode_be_into<const N: usize>(bytes: &[u8; N], out: &mut Self) {
        *out = Self::from_be_bytes(bytes);
    }

    /// OS2IP (RFC 8017 section 4.2) for ragged input: accept any `bytes.len()`
    /// up to the capacity, left zero-padded (leading zeros in the input are
    /// harmless), and reject oversize input.
    ///
    /// This is the boundary-only import for real key material, which arrives
    /// DER-minimally encoded (a 2048-bit modulus may serialize to 255 bytes, or
    /// 257 with a leading 0x00 that strips to 256). Timing may depend on the
    /// *length* of the input, which is acceptable: DER lengths are public
    /// metadata. The byte *values* are handled without branching.
    pub fn from_be_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::BYTES {
            return Err(DecodeError::InputTooLong(bytes.len(), Self::BYTES));
        }
        let mut out = Self::ZERO;
        // Walk from the input's last byte (least significant) forward, filling
        // limbs little-endian; bytes beyond the input length stay zero.
        for (k, &byte) in bytes.iter().rev().enumerate() {
            let limb_index = k / WORD_BYTES;
            let shift = 8 * (k % WORD_BYTES);
            out.as_limbs_mut()[limb_index].0 |= (byte as Word) << shift;
        }
        Ok(out)
    }

    /// Read the limb at public index `i`. Building block for later masked-table
    /// operations; the index must be public data.
    pub const fn limb(&self, i: usize) -> Limb {
        self.as_limbs()[i]
    }

    /// Write the limb at public index `i`. The index must be public data.
    pub const fn set_limb(&mut self, i: usize, value: Limb) {
        self.as_limbs_mut()[i] = value;
    }
}
