//! Probes: facts about `crypto/rsa` at the pinned baseline that the audit's documents state,
//! each pinned by a test so that the statement can be re-run.
//!
//! A probe asserts what the code *does*, not what it should do: a passing probe is evidence
//! for an observation, and a probe that starts failing means upstream changed the behaviour
//! and the observation has to be revisited. Run in both profiles:
//!
//!     cargo test --test probes            # debug
//!     cargo test --release --test probes  # release
//!
//! Ported to `30cbbab` in WP14.3. The first pass's probes of concerns upstream has since
//! answered are now the regression tests of the answers (their names say `refused`, `is an
//! error`): the same inputs, the opposite assertion. Two of the first pass's probes have no
//! run-time form any more, because what they showed no longer compiles; they are in
//! `compile_checks/` (key establishment toward the verify-only sizes, finding F-04;
//! inconsistent width parameters, finding F-06). The probes of gaps that are still open are
//! unchanged in what they assert.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotSigningKey,
    OneShotVerifyingKey,
};
use bouncycastle_core::traits::{PublicKey, SignatureSigner};
use bouncycastle_ec::montgomery;
use bouncycastle_sha2::{SHA256, SHA512};
use bouncycastle_utils::const_str::ConstStr;
use rsa_audit_harness::keys::{
    RsaPrivateComponents, RsaPrivateKey, RsaPublicComponents, RsaPublicKey,
};
use rsa_audit_harness::modexp::{self, MontgomeryContext};
use rsa_audit_harness::rsassa::{
    RsaRandomizedSignatureAlgorithm, RsaSignatureAlgorithm, sign_from_hash,
    sign_from_hash_deterministic, sign_from_hash_with_salt, verify_from_hash,
};
use rsa_audit_harness::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use rsa_audit_harness::rsassa_pss::{PssParams, RSASSA_PSS, SaltedPss};
use rsa_audit_harness::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey};
use rsa_audit_harness::size::{RsaSigningSize, RsaSize};
use rsa_audit_harness::stream_rng::StreamRng;
use rsa_audit_harness::{RSA1024, RSA2048, api};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;

type Pk = RsaPublicComponents<RSA2048>;
type Sk = RsaPrivateComponents<RSA2048>;
type V15 = RSASSA_PKCS1_v1_5<RSA2048, SHA256>;
type Pss = RSASSA_PSS<RSA2048, SHA256>;

const TOP_BIT_MESSAGE: &str = "RSA modulus must have its top bit set";

/// A deterministic byte stream (xorshift64*), so the test key is the same on every run.
fn stream(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        out.extend_from_slice(&x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes());
    }
    out.truncate(len);
    out
}

/// One RSA-2048 key pair from the crate's own generator, shared by the probes.
fn key() -> &'static (Pk, Sk) {
    static KEY: OnceLock<(Pk, Sk)> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut rng = StreamRng::new(stream(0x5eed, 4 << 20), SecurityStrength::_256bit);
        RSA2048::keygen(&mut rng).expect("key generation from a 4 MiB stream")
    })
}

fn limb<const N: usize>(v: u64) -> [u64; N] {
    let mut a = [0u64; N];
    a[0] = v;
    a
}

fn panics<R>(f: impl FnOnce() -> R) -> bool {
    catch_unwind(AssertUnwindSafe(f)).is_err()
}

fn is_top_bit_error<T>(r: &Result<T, SignatureError>) -> bool {
    matches!(r, Err(SignatureError::DecodingError(m)) if *m == TOP_BIT_MESSAGE)
}

// ---------------------------------------------------------------------------------------
// Key construction (findings F-02; plan G3, G6, G7, I1; observations N4, N12)

/// Finding F-02, fixed by `e395060`. The first pass built an RSA-2048 signature key type over
/// a 961-bit modulus and over n = 15. Every constructor refuses both now, with the message
/// about the top bit; the key-establishment wrapper refused the first before and still does.
#[test]
fn a_key_type_refuses_a_modulus_shorter_than_its_size() {
    let mut n = [0u64; 32];
    n[0] = 0xffff_ffff_ffff_fffb;
    n[15] = 1;
    assert!(is_top_bit_error(&RsaPublicComponents::<RSA2048>::new(&n, 65537)));
    assert!(is_top_bit_error(&RsaPublicKey::<V15>::new(&n, 65537)));
    assert!(RsaKEMPublicKey::<RSA2048>::new(&n, 65537).is_err());

    // The private side: p = 3, q = 5 gave the four-bit modulus 15 in a 2048-bit key type.
    let small = RsaPrivateComponents::<RSA2048>::from_crt_components(
        &limb(3),
        &limb(5),
        &limb(1),
        &limb(1),
        &limb(2),
        65537,
    );
    assert!(is_top_bit_error(&small));
    assert!(
        RsaKEMPrivateKey::<RSA2048>::from_crt_components(
            &limb(3),
            &limb(5),
            &limb(1),
            &limb(1),
            &limb(2),
            65537
        )
        .is_err()
    );
}

/// Map flag 5 at the first pass: `p = 1` passed the constructor. It is refused now, as a
/// consequence of the modulus's length (n = 3 is short), not of a rule about p.
///
/// Observation N4 stands for a direct caller: the public constructor still builds a context
/// over the modulus 1, and it holds `R mod n = 1` where the residue is 0.
#[test]
fn p_equal_to_one_is_refused_and_a_context_over_one_still_exists() {
    let sk = RsaPrivateComponents::<RSA2048>::from_crt_components(
        &limb(1),
        &limb(3),
        &limb(0),
        &limb(1),
        &limb(0),
        65537,
    );
    assert!(is_top_bit_error(&sk));
    let ctx = MontgomeryContext::<16>::for_public_modulus(&limb(1)).expect("an odd modulus");
    let (_, _, r_mod_n, r2_mod_n) = modexp::probe::ctx_fields(&ctx);
    assert_eq!((r_mod_n, r2_mod_n), (limb(1), limb(1)));
}

/// Observation N12. The key docs say `p` and `q` "need not be the same bit length"; with a
/// full-length modulus they must be. A 1024-bit p with a 1023-bit q is refused, and the
/// message is the one about the modulus's top bit.
#[test]
fn primes_of_unequal_length_are_refused() {
    let p = [u64::MAX; 16]; // 2^1024 - 1: odd, 1024 bits
    let mut q = [u64::MAX; 16];
    q[15] = u64::MAX >> 1; // 2^1023 - 1: odd, 1023 bits
    let r = RsaPrivateComponents::<RSA2048>::from_crt_components(
        &p,
        &q,
        &limb(0),
        &limb(0),
        &limb(0),
        65537,
    );
    assert!(is_top_bit_error(&r));
    // The least 1024-bit q is admitted beside the largest p: both have exactly 1024 bits.
    let mut q_min = limb::<16>(1);
    q_min[15] = 1 << 63;
    assert!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(
            &p,
            &q_min,
            &limb(0),
            &limb(0),
            &limb(0),
            65537
        )
        .is_ok()
    );
}

/// G6, open: a signature public key takes any odd `e >= 3`; the key-establishment key needs
/// 65537. Since `3f27178` the rule covers the private key's copy of `e` as well.
#[test]
fn a_signature_public_key_accepts_small_exponents() {
    let (pk, sk) = key();
    assert!(RsaPublicComponents::<RSA2048>::new(pk.n(), 3).is_ok());
    assert!(RsaPublicComponents::<RSA2048>::new(pk.n(), 1).is_err());
    assert!(RsaPublicComponents::<RSA2048>::new(pk.n(), 4).is_err());
    assert!(RsaKEMPublicKey::<RSA2048>::new(pk.n(), 3).is_err());
    assert!(RsaKEMPublicKey::<RSA2048>::new(pk.n(), 65535).is_err());
    assert!(RsaKEMPublicKey::<RSA2048>::new(pk.n(), 65537).is_ok());

    let (p, q, dp, dq, qinv) = api::private_parts::<RSA2048>(sk);
    let with = |e| RsaPrivateComponents::<RSA2048>::from_crt_components(&p, &q, &dp, &dq, &qinv, e);
    assert!(with(3).is_ok() && with(u64::MAX).is_ok());
    assert!(with(1).is_err() && with(4).is_err() && with(0).is_err());
    let kem = |e| RsaKEMPrivateKey::<RSA2048>::from_crt_components(&p, &q, &dp, &dq, &qinv, e);
    assert!(kem(3).is_err() && kem(65535).is_err() && kem(65537).is_ok());
}

/// G5 / map flag 14, open: one set of components is a key for any algorithm of its size.
#[test]
fn key_material_is_retyped_freely() {
    let (pk, sk) = key();
    let v15_sk: RsaPrivateKey<V15> = sk.key();
    let pss_sk: RsaPrivateKey<Pss> = v15_sk.components().key();
    let third_sk: RsaPrivateKey<RSASSA_PKCS1_v1_5<RSA2048, SHA512>> = pss_sk.components().key();
    let sig = third_sk.sign_deterministic(b"one key, a third algorithm", None).unwrap();
    let third_pk: RsaPublicKey<RSASSA_PKCS1_v1_5<RSA2048, SHA512>> = pk.key();
    assert!(third_pk.verify(b"one key, a third algorithm", None, &sig).is_ok());
    // The same five integers are also a key-establishment key.
    let (p, q, dp, dq, qinv) = api::private_parts::<RSA2048>(sk);
    assert!(
        RsaKEMPrivateKey::<RSA2048>::from_crt_components(&p, &q, &dp, &dq, &qinv, sk.e()).is_ok()
    );
}

/// Plan WP4: the private components print redacted; the modulus, which is public, prints.
#[test]
fn private_components_print_redacted() {
    let (_, sk) = key();
    let (p, ..) = api::private_parts::<RSA2048>(sk);
    let text = format!("{sk:?} {:?}", sk.key::<V15>());
    assert!(text.contains("<redacted>"));
    for l in p {
        assert!(!text.contains(&format!("{l}")) && !text.contains(&format!("{l:x}")));
    }
}

/// The encodings since `6c58545` and `3f27178`: `n || e` in K_LEN + 8 bytes, the private key
/// in 5 * K_LEN / 2 + 8, `e` in eight big-endian bytes at the end of each. A key stored in
/// the first pass's layout (four bytes of `e`, none in the private key) does not decode.
#[test]
fn the_key_encodings_carry_an_eight_byte_exponent() {
    let (pk, _) = key();
    let key: RsaPublicKey<V15> = pk.key();
    let enc: [u8; 264] = key.encode();
    assert_eq!(&enc[256..], &65537u64.to_be_bytes());
    assert_eq!(<RsaPublicKey<V15> as PublicKey<264>>::from_bytes(&enc).unwrap(), key);
    assert!(<RsaPublicKey<V15> as PublicKey<264>>::from_bytes(&enc[..260]).is_err());
    assert_eq!((RSA2048::PK_LEN, RSA2048::SK_LEN), (264, 648));
}

// ---------------------------------------------------------------------------------------
// The verify-only sizes and the raw primitives (finding F-04; observation N14)

/// Finding F-04 is a compile-time fact now (`compile_checks/generated.py`, family f04). What
/// remains at RSA-1024, as observation N14 records: the key-establishment public key type
/// still exists and encodes, with no role; and the raw public exponentiation is a public
/// method of the size, so textbook RSAEP toward a 1024-bit modulus is one call.
#[test]
fn rsa_1024_keeps_a_key_type_without_a_role_and_the_raw_public_primitive() {
    let n = [u64::MAX; 16]; // odd, top bit set: all the constructor asks
    let pk = RsaKEMPublicKey::<RSA1024>::new(&n, 65537).expect("the type exists at RSA-1024");
    let enc: [u8; 136] = pk.encode();
    assert_eq!(&enc[128..], &65537u64.to_be_bytes());
    // x^65537 mod (2^1024 - 1) for x = 2: 65537 = 1 mod 1024, so the result is 2.
    assert_eq!(RSA1024::public_exp(&n, 65537, &limb(2)), limb(2));
}

/// N14 and plan T6: `RsaSize::public_exp` panics on an even modulus, as it documents; a key
/// never has one. The private primitive is public as well and carries its result check.
#[test]
fn the_raw_primitives_are_public_methods_of_the_size() {
    let (pk, sk) = key();
    let even = {
        let mut n = *pk.n();
        n[0] &= !1;
        n
    };
    assert!(panics(|| RSA2048::public_exp(&even, 65537, &limb(2))));
    let mut y = [0u64; 32];
    assert!(RSA2048::crt_exp(sk, &limb(2), &mut y).to_bool());
    assert_eq!(RSA2048::public_exp(pk.n(), pk.e(), &y), limb(2));
}

// ---------------------------------------------------------------------------------------
// The result check (plan C7 to C9; decision D4)

/// Plan C9, carried between sessions: a private key holds `e`, and nothing checks that it is
/// the key's. With a foreign odd exponent an ordinary signature fails at the check, with
/// `ComputationFault` -- but the check still passes for the inputs 0, 1 and n - 1, and the
/// value released for them is the right one. "A wrong e always fails" is false.
#[test]
fn a_foreign_exponent_fails_signing_but_not_on_every_input() {
    let (pk, sk) = key();
    let (p, q, dp, dq, qinv) = api::private_parts::<RSA2048>(sk);
    let foreign = RsaPrivateComponents::<RSA2048>::from_crt_components(&p, &q, &dp, &dq, &qinv, 3)
        .expect("the constructor does not relate e to the components");
    let signed = sign_from_hash_deterministic::<V15, 256>(&foreign.key(), &[0x22u8; 32]);
    assert_eq!(signed, Err(SignatureError::ComputationFault));

    let mut n_minus_1 = *pk.n();
    n_minus_1[0] -= 1; // n is odd
    for x in [limb::<32>(0), limb(1), n_minus_1] {
        let mut y = [u64::MAX; 32];
        assert!(RSA2048::crt_exp(&foreign, &x, &mut y).to_bool());
        assert_eq!(y, x);
    }
    // An ordinary input: refused, and nothing of the result comes out.
    let mut y = [u64::MAX; 32];
    assert!(!RSA2048::crt_exp(&foreign, &limb(2), &mut y).to_bool());
    assert_eq!(y, [0u64; 32]);
}

// ---------------------------------------------------------------------------------------
// The `*_from_hash` entry points (finding F-03; plan E11)

/// Finding F-03, fixed by `a2a8f0c`, `5f35d69`, `80d8651`. In the first pass a 20-byte
/// "digest" under the SHA-256 algorithm was signed in a release build into a DigestInfo that
/// names SHA-256 over 20 bytes, and verified; a debug build panicked. Both profiles return
/// `LengthError` now, from signing and from verifying, and the malformed DigestInfo is
/// neither produced nor accepted when it is made by other means.
#[test]
fn v1_5_from_hash_refuses_a_digest_of_the_wrong_length() {
    let (pk, sk) = key();
    let (pk_c, sk_c) = (pk, sk);
    let (pk, sk): (RsaPublicKey<V15>, RsaPrivateKey<V15>) = (pk.key(), sk.key());
    let short = [0x11u8; 20];
    let is_len = |r: &Result<_, SignatureError>| matches!(r, Err(SignatureError::LengthError(_)));
    assert!(is_len(&sign_from_hash_deterministic::<V15, 256>(&sk, &short).map(|_| ())));
    assert!(is_len(&verify_from_hash::<V15, 256>(&pk, &short, &[0u8; 256])));
    assert!(is_len(&sign_from_hash_deterministic::<V15, 256>(&sk, &[0u8; 33]).map(|_| ())));

    // The first pass's malformed encoding, built here by hand and signed with the raw
    // primitive: 00 01 FF..FF 00 || DigestInfo(SHA-256 OID, NULL, a 20-byte OCTET STRING).
    let tail = [
        0x30, 0x25, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x14,
    ];
    let mut em = [0xffu8; 256];
    em[0] = 0x00;
    em[1] = 0x01;
    em[256 - 20 - tail.len() - 1] = 0x00;
    em[256 - 20 - tail.len()..256 - 20].copy_from_slice(&tail);
    em[256 - 20..].copy_from_slice(&short);
    let mut s = [0u64; 32];
    assert!(RSA2048::crt_exp(sk_c, &RSA2048::limbs_from_be_bytes(&em), &mut s).to_bool());
    let forged = RSA2048::be_bytes_from_limbs(&s);
    assert_eq!(RSA2048::be_bytes_from_limbs(&RSA2048::public_exp(pk_c.n(), pk_c.e(), &s)), em);
    assert!(is_len(&verify_from_hash::<V15, 256>(&pk, &short, &forged)));
    assert_eq!(
        verify_from_hash::<V15, 256>(&pk, &[0x11u8; 32], &forged),
        Err(SignatureError::SignatureVerificationFailed)
    );

    // The same calls with the right length behave as specified.
    let digest = [0x22u8; 32];
    let sig = sign_from_hash_deterministic::<V15, 256>(&sk, &digest).unwrap();
    assert!(verify_from_hash::<V15, 256>(&pk, &digest, &sig).is_ok());
    assert!(is_len(&verify_from_hash::<V15, 256>(&pk, &digest[..31], &sig)));
}

/// Finding F-03, the PSS half: a salt or digest of the wrong length panicked in both
/// profiles. It is an error in both now, and `sign_from_hash` checks the digest's length
/// before it draws anything from the RNG.
#[test]
fn pss_from_hash_refuses_a_wrong_length_without_a_panic() {
    let (pk, sk) = key();
    let (pk, sk): (RsaPublicKey<Pss>, RsaPrivateKey<Pss>) = (pk.key(), sk.key());
    let (digest, salt) = ([0x33u8; 32], [0x44u8; 32]);
    let sig = sign_from_hash_with_salt::<Pss, 256>(&sk, &digest, &salt).unwrap();
    assert!(verify_from_hash::<Pss, 256>(&pk, &digest, &sig).is_ok());

    let is_len = |r: Result<[u8; 256], SignatureError>| matches!(r, Err(SignatureError::LengthError(_)));
    assert!(!panics(|| sign_from_hash_with_salt::<Pss, 256>(&sk, &digest, &salt[..31])));
    assert!(is_len(sign_from_hash_with_salt::<Pss, 256>(&sk, &digest, &salt[..31])));
    assert!(is_len(sign_from_hash_with_salt::<Pss, 256>(&sk, &digest[..20], &salt)));
    assert!(matches!(
        verify_from_hash::<Pss, 256>(&pk, &digest[..20], &sig),
        Err(SignatureError::LengthError(_))
    ));
    assert!(verify_from_hash::<Pss, 256>(&pk, &digest[..20], &[0x01u8; 256]).is_err());

    let mut rng = StreamRng::new(stream(9, 64), SecurityStrength::_256bit);
    assert!(is_len(sign_from_hash::<Pss, 256>(&sk, &digest[..20], &mut rng)));
    assert_eq!((rng.calls(), rng.consumed()), (0, 0));
    assert!(sign_from_hash::<Pss, 256>(&sk, &digest, &mut rng).is_ok());
    assert_eq!((rng.calls(), rng.consumed()), (1, 32));
}

/// Finding F-03, row (a) of plan WP14.4, its last clause ("the output buffer is not written").
/// The four `*_from_hash` entry points return their result: there is no buffer, and an error
/// carries no bytes. A buffer exists on the signing roles (`sign_out`,
/// `sign_deterministic_out`, a signer's final), and the digest those sign is the roles' own,
/// so a wrong length cannot arise there. What can fail there leaves the buffer zero, whatever
/// it held: a refused context, an RNG that delivers short, a result that fails its check.
#[test]
fn a_failed_signature_leaves_the_output_buffer_zero() {
    let (pk, sk) = key();
    let (v15, pss): (RsaPrivateKey<V15>, RsaPrivateKey<Pss>) = (sk.key(), sk.key());
    let msg = b"an output buffer";
    let dirty = [0xA5u8; 256];
    let is_len = |r: Result<usize, SignatureError>| matches!(r, Err(SignatureError::LengthError(_)));

    // A refused context, deterministic and randomized; nothing is drawn for it.
    let mut out = dirty;
    assert!(is_len(v15.sign_deterministic_out(msg, Some(b"ctx"), &mut out)));
    assert_eq!(out, [0u8; 256]);
    let mut out = dirty;
    let mut rng = StreamRng::new(stream(21, 64), SecurityStrength::_256bit);
    assert!(is_len(pss.sign_out(&mut rng, msg, Some(b"ctx"), &mut out)));
    assert_eq!((out, rng.calls()), ([0u8; 256], 0));

    // An RNG one byte short of the salt.
    let mut out = dirty;
    let mut short = StreamRng::new(stream(22, 31), SecurityStrength::_256bit);
    assert!(matches!(pss.sign_out(&mut short, msg, None, &mut out), Err(SignatureError::RNGError(_))));
    assert_eq!(out, [0u8; 256]);

    // A result that fails its check (a key that holds a foreign `e`): one-shot, and through
    // the streaming signer's final.
    let (p, q, dp, dq, qinv) = api::private_parts::<RSA2048>(sk);
    let foreign: RsaPrivateKey<V15> =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&p, &q, &dp, &dq, &qinv, 3)
            .expect("the constructor does not relate e to the components")
            .key();
    let mut out = dirty;
    assert_eq!(foreign.sign_deterministic_out(msg, None, &mut out), Err(SignatureError::ComputationFault));
    assert_eq!(out, [0u8; 256]);
    let mut out = dirty;
    let mut signer = foreign.create_signer_deterministic(None).unwrap();
    signer.do_update(msg);
    assert_eq!(signer.do_final_out(&mut out), Err(SignatureError::ComputationFault));
    assert_eq!(out, [0u8; 256]);

    // The control: a signature overwrites the buffer, and verifies.
    let mut out = dirty;
    assert_eq!(v15.sign_deterministic_out(msg, None, &mut out), Ok(256));
    assert!(out != dirty && out != [0u8; 256]);
    let pk: RsaPublicKey<V15> = pk.key();
    assert!(pk.verify(msg, None, &out).is_ok());
}

/// A parameter set of a caller's own, as the open `PssParams` trait allows: MGF1 over SHA-256
/// and a salt of `S` bytes.
struct OwnSalt<const S: usize>;

impl<const S: usize> PssParams<SHA256> for OwnSalt<S> {
    const SALT_LEN: usize = S;
    const NAME_SUFFIX: ConstStr<32> = ConstStr::concat(&["-own"]);

    fn mask(seed: &[u8], mask: &mut [u8]) {
        mask.fill(0);
        api::mgf1_xor::<SHA256>(seed, mask);
    }
}

impl<const S: usize> SaltedPss for OwnSalt<S> {}

type Own<const S: usize> = RSASSA_PSS<RSA2048, SHA256, OwnSalt<S>>;

/// Where finding F-03's "an error, never a panic" ends: map flag 13, second half, open (plan
/// E7; for WP7). The fix checks the slices against the lengths the algorithm's type states.
/// It does not bound those lengths. `PssParams` documents a salt of "at most 64" bytes, and
/// only the two entry points that draw the salt enforce it (a `const` assertion: the
/// compile checks, family flag13). `sign_from_hash_with_salt`, `emsa_encode` and
/// `emsa_verify` take a foreign parameter set as it is: up to hLen + sLen = 128 the encoding
/// works, and past it the 136-byte `M'` buffer is indexed out of bounds (`emsa_pss.rs:74`,
/// `:149`): a panic in both profiles, with slices of exactly the lengths asked for.
#[test]
fn a_foreign_pss_parameter_set_past_its_documented_salt_bound_panics() {
    let (pk, sk) = key();
    let digest = [0x33u8; 32];

    // 96 bytes of salt with SHA-256 fill the buffer exactly: it signs and verifies.
    let salt = [0x44u8; 97];
    let sig = sign_from_hash_with_salt::<Own<96>, 256>(&sk.key(), &digest, &salt[..96]).unwrap();
    assert!(verify_from_hash::<Own<96>, 256>(&pk.key(), &digest, &sig).is_ok());

    // 97 do not. The length checks pass, since the slices are what the type asks for.
    assert!(panics(|| sign_from_hash_with_salt::<Own<97>, 256>(&sk.key(), &digest, &salt)));
    assert!(panics(|| Own::<97>::emsa_encode::<256>(&digest, &salt)));
    // A slice of another length is still the error of F-03's fix, before the buffer is reached.
    assert!(matches!(
        sign_from_hash_with_salt::<Own<97>, 256>(&sk.key(), &digest, &salt[..96]),
        Err(SignatureError::LengthError(_))
    ));

    // The verifier reaches the same buffer once an encoding has the right shape. Built by
    // hand: DB = PS || 01 || salt under MGF1(H), for an H whose mask leaves the top bit clear.
    let db_len = 256 - 32 - 1;
    let em = (0u8..=255)
        .find_map(|x| {
            let h = [x; 32];
            let mut db = vec![0u8; db_len];
            db[db_len - 97 - 1] = 0x01;
            db[db_len - 97..].copy_from_slice(&salt);
            api::mgf1_xor::<SHA256>(&h, &mut db);
            (db[0] & 0x80 == 0).then(|| {
                let mut em = [0u8; 256];
                em[..db_len].copy_from_slice(&db);
                em[db_len..255].copy_from_slice(&h);
                em[255] = 0xbc;
                em
            })
        })
        .expect("some H gives a mask with its top bit clear");
    assert!(panics(|| Own::<97>::emsa_verify::<256>(&digest, &em)));
    // Under the crate's own parameters the same bytes are a refusal, not a panic.
    assert!(!Pss::emsa_verify::<256>(&digest, &em));
}

// ---------------------------------------------------------------------------------------
// The signature context (plan X1)

/// `2c4fbc1`: a non-empty `ctx` is `LengthError`, from signing and from verifying; `None` and
/// the empty context are the same. The randomized signer refuses before it draws a salt.
#[test]
fn a_non_empty_context_is_refused_before_anything_is_drawn() {
    let (pk, sk) = key();
    let (v15_pk, v15_sk): (RsaPublicKey<V15>, RsaPrivateKey<V15>) = (pk.key(), sk.key());
    let msg = b"RSA takes no context";
    let is_len = |r: &Result<(), SignatureError>| matches!(r, Err(SignatureError::LengthError(_)));

    let sig = v15_sk.sign_deterministic(msg, None).unwrap();
    assert_eq!(v15_sk.sign_deterministic(msg, Some(b"")).unwrap(), sig);
    assert!(is_len(&v15_sk.sign_deterministic(msg, Some(b"ctx")).map(|_| ())));
    assert!(v15_pk.verify(msg, None, &sig).is_ok() && v15_pk.verify(msg, Some(b""), &sig).is_ok());
    assert!(is_len(&v15_pk.verify(msg, Some(b"ctx"), &sig)));

    let (pss_pk, pss_sk): (RsaPublicKey<Pss>, RsaPrivateKey<Pss>) = (pk.key(), sk.key());
    let mut rng = StreamRng::new(stream(11, 256), SecurityStrength::_256bit);
    assert!(is_len(&pss_sk.sign(&mut rng, msg, Some(b"ctx")).map(|_| ())));
    assert_eq!(rng.calls(), 0, "nothing is drawn for a refused context");
    let sig = pss_sk.sign(&mut rng, msg, None).unwrap();
    assert_eq!(rng.calls(), 1);
    assert!(pss_pk.verify(msg, None, &sig).is_ok());
    assert!(is_len(&pss_pk.verify(msg, Some(b"ctx"), &sig)));
}

// ---------------------------------------------------------------------------------------
// What a short modulus did to RSASSA-PSS (finding F-02; plan E6)

#[path = "data/short_modulus.rs"]
mod short_modulus;

/// The first pass's 2044-bit key in an RSA-2048 key type, with which the crate's PSS neither
/// signed nor verified as RFC 8017 does (`audit/ref/make_short_modulus_probe.py`; the data
/// file is the first pass's, unchanged). The key can no longer be built, on either half, so
/// the probe's signatures have nothing to be checked under: E6's hypothesis is a constructor
/// invariant now.
#[test]
fn the_short_modulus_key_of_the_first_pass_is_refused() {
    use short_modulus::*;
    let private = RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 65537);
    assert!(is_top_bit_error(&private));
    let n: [u64; 32] = montgomery::widening_mul::<16, 32>(&P, &Q);
    assert_eq!(64 * 32 - n[31].leading_zeros() as usize, MODULUS_BITS);
    assert!(is_top_bit_error(&RsaPublicComponents::<RSA2048>::new(&n, 65537)));
    assert!(RsaKEMPublicKey::<RSA2048>::new(&n, 65537).is_err());
    // The constants the old probe compared against are still what the model said then.
    assert_eq!((SIGNABLE.len(), SIG_CRATE.len(), SIG_RFC.len(), M_HASH.len()), (6, 256, 256, 32));
    let _ = (SALT_CRATE, SALT_RFC);
}
