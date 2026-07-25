//! Tests for `bigint::encoding`: BE/LE round-trips, in-place decode, ragged-slice
//! import with padding/oversize cases, and limb get/set.

use crate::bigint::encoding::DecodeError;
use crate::bigint::limb::{Limb, WORD_BYTES, Word};
use crate::bigint::uint::{U1024, Uint};
use bouncycastle_utils::secret::Secret;

type U4 = Uint<4>;
const U4_BYTES: usize = 4 * WORD_BYTES;

#[test]
fn be_roundtrip_and_byte_order() {
    let mut bytes = [0u8; U4_BYTES];
    bytes[0] = 0x01; // most significant byte
    bytes[U4_BYTES - 1] = 0x02; // least significant byte
    let x = U4::from_be_bytes(&bytes);
    // least significant limb holds the last byte
    assert_eq!(x.limb(0).0, 2);
    // most significant limb holds the first byte at its top position
    assert_eq!(x.limb(3).0, (0x01 as Word) << (8 * (WORD_BYTES - 1)));
    let back: [u8; U4_BYTES] = x.to_be_bytes();
    assert_eq!(bytes, back);
}

#[test]
fn le_roundtrip_and_byte_order() {
    let mut bytes = [0u8; U4_BYTES];
    bytes[0] = 0x02; // least significant byte in LE
    bytes[U4_BYTES - 1] = 0x01; // most significant byte in LE
    let x = U4::from_le_bytes(&bytes);
    assert_eq!(x.limb(0).0, 2);
    assert_eq!(x.limb(3).0, (0x01 as Word) << (8 * (WORD_BYTES - 1)));
    let back: [u8; U4_BYTES] = x.to_le_bytes();
    assert_eq!(bytes, back);
    // LE of a value equals BE reversed
    let be: [u8; U4_BYTES] = x.to_be_bytes();
    for i in 0..U4_BYTES {
        assert_eq!(be[i], bytes[U4_BYTES - 1 - i]);
    }
}

#[test]
fn extreme_values_roundtrip() {
    let zero: [u8; U4_BYTES] = U4::ZERO.to_be_bytes();
    assert_eq!(zero, [0u8; U4_BYTES]);
    assert!(U4::from_be_bytes(&zero) == U4::ZERO);

    let max: [u8; U4_BYTES] = U4::MAX.to_be_bytes();
    assert_eq!(max, [0xFFu8; U4_BYTES]);
    assert!(U4::from_be_bytes(&max) == U4::MAX);

    let mut one = [0u8; U4_BYTES];
    one[U4_BYTES - 1] = 1;
    assert!(U4::from_be_bytes(&one) == U4::ONE);
}

#[test]
fn every_byte_position_is_distinct() {
    // A distinct value in each byte kills any index-arithmetic mutant.
    let mut bytes = [0u8; U4_BYTES];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    let x = U4::from_be_bytes(&bytes);
    let back: [u8; U4_BYTES] = x.to_be_bytes();
    assert_eq!(bytes, back);
    let le: [u8; U4_BYTES] = x.to_le_bytes();
    let y = U4::from_le_bytes(&le);
    assert!(x == y);
}

#[test]
fn decode_be_into_secret() {
    let mut bytes = [0u8; 128]; // U1024 capacity under both widths
    bytes[127] = 0x2A;
    let mut s: Secret<U1024> = Secret::new();
    U1024::decode_be_into(&bytes, &mut s);
    assert_eq!(s.limb(0).0, 0x2A);
    s.zeroize();
    assert!(*s == U1024::ZERO);
}

#[test]
fn from_be_slice_padding_and_rejection() {
    // shorter input is left zero-padded: value is preserved
    let x = U4::from_be_slice(&[0x01, 0x02]).unwrap();
    assert_eq!(x.limb(0).0, 0x0102);
    for i in 1..4 {
        assert_eq!(x.limb(i).0, 0);
    }

    // empty input decodes to zero
    assert!(U4::from_be_slice(&[]).unwrap() == U4::ZERO);

    // leading zeros are harmless: same value as without them
    let full = [0u8; U4_BYTES];
    assert!(U4::from_be_slice(&full).unwrap() == U4::ZERO);
    let y = U4::from_be_slice(&[0x00, 0x00, 0x01, 0x02]).unwrap();
    assert!(x == y);

    // exactly capacity-sized input matches the array form
    let mut cap = [0u8; U4_BYTES];
    for (i, b) in cap.iter_mut().enumerate() {
        *b = i as u8;
    }
    assert!(U4::from_be_slice(&cap).unwrap() == U4::from_be_bytes(&cap));

    // oversize input is rejected, even when the extra bytes are zero
    let oversize = [0u8; U4_BYTES + 1];
    assert_eq!(
        U4::from_be_slice(&oversize),
        Err(DecodeError::InputTooLong(U4_BYTES + 1, U4_BYTES))
    );
}

#[test]
fn limb_get_set() {
    let mut x = U4::ZERO;
    x.set_limb(2, Limb(0xAB));
    assert_eq!(x.limb(2).0, 0xAB);
    assert_eq!(x.limb(0).0, 0);
    assert_eq!(x.as_limbs()[2].0, 0xAB);
}
