//! Tests for `bigint::uint`: consts, accessors, equality, Debug, aliases, and the
//! `Secret<Uint>` integration (zeroize, redaction, constant-time equality).

use crate::bigint::limb::{Limb, WORD_BITS, WORD_BYTES, Word};
use crate::bigint::uint::{U1024, U2048, U4096, U8192, U16384, Uint};
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};

/// Minimal `core::fmt::Write` sink so Debug output is testable under `no_std`
/// (no `format!` without `alloc`).
struct FmtBuf {
    buf: [u8; 256],
    len: usize,
}

impl FmtBuf {
    fn new() -> Self {
        Self { buf: [0; 256], len: 0 }
    }
    fn as_str(&self) -> &str {
        // unwrap justification: bytes are only ever written via write_str from
        // valid &str fragments, so the buffer prefix is always valid UTF-8.
        core::str::from_utf8(&self.buf[..self.len]).unwrap()
    }
}

impl core::fmt::Write for FmtBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

fn debug_str(value: &impl core::fmt::Debug, out: &mut FmtBuf) -> &'static str {
    use core::fmt::Write;
    // unwrap justification: FmtBuf only errors on overflow and every test value
    // fits in its 256-byte buffer.
    write!(out, "{:?}", value).unwrap();
    ""
}

fn contains(haystack: &str, needle: &str) -> bool {
    haystack.as_bytes().windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn consts_and_capacity() {
    assert_eq!(U1024::BITS, 1024);
    assert_eq!(U1024::BYTES, 128);
    assert_eq!(U2048::BITS, 2048);
    assert_eq!(U2048::BYTES, 256);
    assert_eq!(U16384::BITS, 16384);

    // The aliases are width-independent: same byte size under both limb widths.
    assert_eq!(core::mem::size_of::<U2048>(), 256);
    assert_eq!(core::mem::size_of::<U4096>(), 512);
    assert_eq!(core::mem::size_of::<U8192>(), 1024);

    for limb in U2048::ZERO.as_limbs() {
        assert_eq!(limb.0, 0);
    }
    for limb in U2048::MAX.as_limbs() {
        assert_eq!(limb.0, Word::MAX);
    }
    let one = U2048::ONE;
    assert_eq!(one.as_limbs()[0].0, 1);
    for limb in &one.as_limbs()[1..] {
        assert_eq!(limb.0, 0);
    }
}

#[test]
fn accessors_roundtrip() {
    let mut x = U1024::ZERO;
    x.as_limbs_mut()[0] = Limb(7);
    let top = x.as_limbs().len() - 1;
    x.as_limbs_mut()[top] = Limb(9);
    assert_eq!(x.as_limbs()[0].0, 7);
    assert_eq!(x.as_limbs()[top].0, 9);
}

#[test]
fn equality() {
    assert!(U1024::ZERO == U1024::ZERO);
    assert!(U1024::MAX == U1024::MAX);
    assert!(U1024::ZERO != U1024::ONE);
    assert!(U1024::ZERO != U1024::MAX);

    // Differences in the first and in the last limb are both caught (the fold
    // never short-circuits, so position must not matter for the result).
    let mut lo = U1024::ZERO;
    lo.as_limbs_mut()[0] = Limb(1);
    let mut hi = U1024::ZERO;
    let top = hi.as_limbs().len() - 1;
    hi.as_limbs_mut()[top] = Limb(1);
    assert!(lo != U1024::ZERO);
    assert!(hi != U1024::ZERO);
    assert!(lo != hi);
}

#[test]
fn zeroizable_and_secret_integration() {
    // ZEROED is all-zero limbs.
    assert!(U2048::ZEROED == U2048::ZERO);

    // Populate a Secret<Uint> in place through DerefMut, per secret.rs guidance.
    let mut s: Secret<U2048> = Secret::new();
    s.as_limbs_mut()[0] = Limb(0xDEAD_BEEF);
    assert!(*s != U2048::ZERO);

    // Secret's PartialEq (byte-wise constant-time) works out of the box.
    let fresh: Secret<U2048> = Secret::new();
    assert!(s != fresh);

    // zeroize() returns the value to all-zeros.
    s.zeroize();
    assert!(*s == U2048::ZERO);
    assert!(s == fresh);
}

#[test]
fn debug_prints_hex_and_secret_redacts() {
    let mut x = Uint::<2>::ZERO;
    x.as_limbs_mut()[0] = Limb(0xAB);
    x.as_limbs_mut()[1] = Limb(1);

    let mut buf = FmtBuf::new();
    debug_str(&x, &mut buf);
    let s = buf.as_str();
    // Most significant limb first: limb[1] = 1, then limb[0] = 0xab, each
    // zero-padded to the limb's hex width.
    assert!(contains(s, "Uint<2>(0x"));
    assert!(contains(s, "1")); // high limb
    assert!(contains(s, "ab")); // low limb
    assert_eq!(s.len(), "Uint<2>(0x".len() + 2 * (WORD_BYTES * 2) + 1);
    let _ = WORD_BITS; // width used above via WORD_BYTES

    // The same value inside Secret<...> must redact regardless of Uint's Debug.
    let mut secret: Secret<Uint<2>> = Secret::new();
    secret.as_limbs_mut()[0] = Limb(0xAB);
    let mut buf = FmtBuf::new();
    debug_str(&secret, &mut buf);
    let s = buf.as_str();
    assert!(contains(s, "redacted"));
    assert!(!contains(s, "ab"));
}
