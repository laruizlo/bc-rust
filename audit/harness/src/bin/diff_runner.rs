//! Runs differential cases against the audited code.
//!
//!     diff_runner < cases.txt > results.txt
//!
//! One case per line: `id op key=value ...`. One result per line: `id OK v ...`, `id ERR tag`
//! (the function returned an error) or `id PANIC message` (it panicked; each case runs under
//! `catch_unwind`, so a panic is a result, not the end of the run). Integers and limb arrays
//! are big-endian hex without prefix; byte strings are hex, `-` for the empty string.
//! `audit/ref/gen_cases.py` writes the cases and judges the results against the model.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{PrivateKey, PublicKey};
use bouncycastle_ec::{montgomery, nat};
use bouncycastle_sha2::{SHA256, SHA512};
use core::num::NonZeroUsize;
use rsa_audit_harness::keygen::probe as kg;
use rsa_audit_harness::keys::{
    RsaPrivateComponents, RsaPrivateKey, RsaPublicComponents, RsaPublicKey,
};
use rsa_audit_harness::modexp::probe as mx;
use rsa_audit_harness::modexp::{self, MontgomeryContext};
use rsa_audit_harness::rsassa::{
    self, RsaDeterministicSignatureAlgorithm, RsaRandomizedSignatureAlgorithm,
    RsaSignatureAlgorithm,
};
use rsa_audit_harness::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use rsa_audit_harness::rsassa_pss::{Mgf1, NoSalt, RSASSA_PSS};
use rsa_audit_harness::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey};
use rsa_audit_harness::size::{RsaSigningSize, RsaSize};
use rsa_audit_harness::stream_rng::{ShortRng, StreamRng};
use rsa_audit_harness::{
    RSA1024, RSA1536, RSA2048, RSA3072, RSA4096, RSA8192, api, codec, keygen,
};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};

type Res = Result<Vec<String>, String>;

struct Args<'a>(HashMap<&'a str, &'a str>);

impl Args<'_> {
    fn raw(&self, k: &str) -> Result<&str, String> {
        self.0.get(k).copied().ok_or_else(|| format!("missing argument {k}"))
    }

    fn u64(&self, k: &str) -> Result<u64, String> {
        u64::from_str_radix(self.raw(k)?, 16).map_err(|e| format!("{k}: {e}"))
    }

    fn usize(&self, k: &str) -> Result<usize, String> {
        self.raw(k)?.parse::<usize>().map_err(|e| format!("{k}: {e}"))
    }

    fn bytes(&self, k: &str) -> Result<Vec<u8>, String> {
        let s = self.raw(k)?;
        if s == "-" {
            return Ok(Vec::new());
        }
        if s.len() % 2 != 0 {
            return Err(format!("{k}: odd hex length"));
        }
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| format!("{k}: {e}")))
            .collect()
    }

    /// A limb array from exactly `16 * N` big-endian hex digits.
    fn limbs<const N: usize>(&self, k: &str) -> Result<[u64; N], String> {
        let s = self.raw(k)?;
        if s.len() != 16 * N {
            return Err(format!("{k}: expected {} hex digits, got {}", 16 * N, s.len()));
        }
        let mut out = [0u64; N];
        for i in 0..N {
            let chunk = &s[16 * (N - 1 - i)..16 * (N - i)];
            out[i] = u64::from_str_radix(chunk, 16).map_err(|e| format!("{k}: {e}"))?;
        }
        Ok(out)
    }
}

fn hex_limbs(a: &[u64]) -> String {
    a.iter().rev().map(|l| format!("{l:016x}")).collect()
}

fn hex_bytes(a: &[u8]) -> String {
    if a.is_empty() { "-".into() } else { a.iter().map(|b| format!("{b:02x}")).collect() }
}

fn ok(v: Vec<String>) -> Res {
    Ok(v)
}

fn sig_err(e: SignatureError) -> Vec<String> {
    vec!["ERR".into(), format!("{e:?}").replace(' ', "_")]
}

fn strength(bits: usize) -> Result<SecurityStrength, String> {
    Ok(match bits {
        0 => SecurityStrength::None,
        112 => SecurityStrength::_112bit,
        128 => SecurityStrength::_128bit,
        192 => SecurityStrength::_192bit,
        256 => SecurityStrength::_256bit,
        other => return Err(format!("unsupported strength {other}")),
    })
}

// ---------------------------------------------------------------- substrate

fn nat_add<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let (s, c) = nat::add::<L>(&a.limbs("a")?, &a.limbs("b")?);
    ok(vec![hex_limbs(&s), format!("{c:x}")])
}

fn nat_sub<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let (d, b) = nat::sub::<L>(&a.limbs("a")?, &a.limbs("b")?);
    ok(vec![hex_limbs(&d), format!("{b:x}")])
}

fn nat_add_assign<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let mut x: [u64; L] = a.limbs("a")?;
    let c = nat::add_assign(&mut x, &a.limbs("b")?);
    ok(vec![hex_limbs(&x), format!("{c:x}")])
}

fn nat_sub_assign<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let mut x: [u64; L] = a.limbs("a")?;
    let b = nat::sub_assign(&mut x, &a.limbs("b")?);
    ok(vec![hex_limbs(&x), format!("{b:x}")])
}

fn nat_is_zero<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let z = nat::is_zero::<L>(&a.limbs("a")?).to_bool();
    ok(vec![format!("{}", z as u8)])
}

fn widening_mul<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let p: [u64; L2] = montgomery::widening_mul::<L, L2>(&a.limbs("a")?, &a.limbs("b")?);
    ok(vec![hex_limbs(&p)])
}

fn widening_mul_into<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    // The destination starts full of ones: the function documents that it overwrites it.
    let mut p = [u64::MAX; L2];
    montgomery::widening_mul_into::<L, L2>(&a.limbs("a")?, &a.limbs("b")?, &mut p);
    ok(vec![hex_limbs(&p)])
}

fn widening_square<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let p: [u64; L2] = montgomery::widening_square::<L, L2>(&a.limbs("a")?);
    ok(vec![hex_limbs(&p)])
}

fn redc<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let (high, extra) =
        montgomery::redc::<L, L2, L21>(&a.limbs("t")?, &a.limbs("n")?, a.u64("np")?);
    ok(vec![hex_limbs(&high), format!("{extra:x}")])
}

// ---------------------------------------------------------------- modexp

/// The context the kernel operations below run over: the variable-time constructor, the
/// modulus of a differential case being public.
fn ctx<const L: usize>(a: &Args) -> Result<MontgomeryContext<L>, String> {
    MontgomeryContext::<L>::for_public_modulus(&a.limbs("n")?)
        .ok_or_else(|| "context: modulus refused".into())
}

fn ctx_fields_out<const L: usize>(c: &MontgomeryContext<L>) -> Vec<String> {
    let (m, np, r, r2) = mx::ctx_fields(c);
    vec![hex_limbs(&m), format!("{np:016x}"), hex_limbs(&r), hex_limbs(&r2)]
}

fn ctx_public<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    match MontgomeryContext::<L>::for_public_modulus(&a.limbs("n")?) {
        None => ok(vec!["NONE".into()]),
        Some(c) => ok(ctx_fields_out(&c)),
    }
}

/// `for_secret_modulus` tests nothing about its modulus: over an even one a debug build stops
/// at `mont_n_prime`'s assertion and a release build returns a context (plan M12).
fn ctx_secret<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(ctx_fields_out(&MontgomeryContext::<L>::for_secret_modulus(&a.limbs("n")?)))
}

fn double_mod_n_vartime<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&mx::double_mod_n_vartime::<L>(&a.limbs("a")?, &a.limbs("n")?))])
}

fn pow2_mod_vartime<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&mx::pow2_mod_vartime::<L>(a.usize("bits")? as u32, &a.limbs("n")?))])
}

fn pow2_ct<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&mx::pow2_mod_ct::<L>(a.usize("bits")? as u32, &a.limbs("n")?))])
}

/// The subtract decisions of `pow2_mod_vartime(bits, n)`, one character per doubling, and its
/// result. `double_mod_n_vartime` returns `diff` exactly when it takes its branch, and
/// `diff != doubled` because `n != 0`, so comparing its output with the plain doubling
/// recovers each decision from the function's own results. Since `04305e0` this is the
/// variable-time form only, which the crate runs over the public `n` alone (plan M2', M13).
fn pow2_trace<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let n: [u64; L] = a.limbs("n")?;
    let bits = a.usize("bits")?;
    let mut acc = [0u64; L];
    acc[0] = 1;
    let mut trace = String::with_capacity(bits);
    for _ in 0..bits {
        let (doubled, _) = nat::add(&acc, &acc);
        let next = mx::double_mod_n_vartime::<L>(&acc, &n);
        trace.push(if next != doubled { '1' } else { '0' });
        acc = next;
    }
    if acc != mx::pow2_mod_vartime::<L>(bits as u32, &n) {
        return Err("the stepped chain and pow2_mod_vartime disagree".into());
    }
    ok(vec![trace, hex_limbs(&acc)])
}

fn redc_normalize<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let r = mx::redc_normalize::<L, L2, L21>(&a.limbs("t")?, &a.limbs("n")?, a.u64("np")?);
    ok(vec![hex_limbs(&r)])
}

fn mont_mul<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let r = mx::mont_mul::<L, L2, L21>(
        &a.limbs("a")?,
        &a.limbs("b")?,
        &a.limbs("n")?,
        a.u64("np")?,
    );
    ok(vec![hex_limbs(&r)])
}

fn mont_square<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let r = mx::mont_square::<L, L2, L21>(&a.limbs("a")?, &a.limbs("n")?, a.u64("np")?);
    ok(vec![hex_limbs(&r)])
}

fn to_montgomery<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&mx::to_montgomery::<L, L2, L21>(&a.limbs("a")?, &ctx(a)?))])
}

fn from_montgomery<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&mx::from_montgomery::<L, L2, L21>(&a.limbs("a")?, &ctx(a)?))])
}

fn mul_mod<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let r = modexp::mul_mod::<L, L2, L21>(&a.limbs("a")?, &a.limbs("b")?, &ctx(a)?);
    ok(vec![hex_limbs(&r)])
}

fn sub_mod<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&modexp::sub_mod::<L>(&a.limbs("a")?, &a.limbs("b")?, &a.limbs("m")?))])
}

fn ct_shift_in_bit_mod<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let r = mx::ct_shift_in_bit_mod::<L>(&a.limbs("acc")?, a.u64("bit")?, &a.limbs("m")?);
    ok(vec![hex_limbs(&r)])
}

fn ct_select_array<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let r = mx::ct_select_array::<L>(a.u64("mask")? == 1, &a.limbs("a")?, &a.limbs("b")?);
    ok(vec![hex_limbs(&r)])
}

fn ct_swap_array<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let (mut x, mut y): ([u64; L], [u64; L]) = (a.limbs("a")?, a.limbs("b")?);
    mx::ct_swap_array(a.u64("mask")? == 1, &mut x, &mut y);
    ok(vec![hex_limbs(&x), hex_limbs(&y)])
}

fn mod_pow<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let r = modexp::mod_pow::<L, L2, L21>(&a.limbs("base")?, &a.limbs("exp")?, &ctx(a)?);
    ok(vec![hex_limbs(&r)])
}

fn mod_pow_public_exponent<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let r = modexp::mod_pow_public_exponent::<L, L2, L21>(&a.limbs("base")?, a.u64("e")?, &ctx(a)?);
    ok(vec![hex_limbs(&r)])
}

fn reduce_wide<const WIDE: usize, const NARROW: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&modexp::reduce_wide::<WIDE, NARROW>(&a.limbs("v")?, &a.limbs("m")?))])
}

// ---------------------------------------------------------------- rsa_core, codec

fn public_exp<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let r = api::public_exp::<L, L2, L21>(&a.limbs("n")?, a.u64("e")?, &a.limbs("x")?);
    ok(vec![hex_limbs(&r)])
}

fn crt_exp<
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
>(
    a: &Args,
) -> Res {
    let r = api::crt_exp::<L, L2, L21, HALF, HALF2, HALF21>(
        &a.limbs("p")?,
        &a.limbs("q")?,
        &a.limbs("dp")?,
        &a.limbs("dq")?,
        &a.limbs("qinv")?,
        &a.limbs("m")?,
    );
    ok(vec![hex_limbs(&r)])
}

/// `crt_exp_checked`: the verdict and `out`. `out` starts full of ones, so a path that left
/// it unwritten would show (plan C7: `out` is `y` or zero, on every path).
fn crt_exp_checked<
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
>(
    a: &Args,
) -> Res {
    let mut out = [u64::MAX; L];
    let verdict = api::crt_exp_checked::<L, L2, L21, HALF, HALF2, HALF21>(
        &a.limbs("p")?,
        &a.limbs("q")?,
        &a.limbs("dp")?,
        &a.limbs("dq")?,
        &a.limbs("qinv")?,
        &a.limbs("n")?,
        a.u64("e")?,
        &a.limbs("x")?,
        &mut out,
    );
    ok(vec![format!("{}", verdict as u8), hex_limbs(&out)])
}

fn codec_round_trip<const L: usize, const BYTES: usize>(a: &Args) -> Res {
    let bytes: [u8; BYTES] =
        a.bytes("x")?.try_into().map_err(|_| "x: wrong byte length".to_string())?;
    let limbs = codec::limbs_from_be_bytes::<L, BYTES>(&bytes);
    let back = codec::be_bytes_from_limbs::<L, BYTES>(&limbs);
    ok(vec![hex_limbs(&limbs), hex_bytes(&back)])
}

// ---------------------------------------------------------------- keygen

fn mod_u64<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![format!("{:x}", kg::mod_u64::<L>(&a.limbs("a")?, a.u64("m")?))])
}

fn mul_u64_add<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let (out, carry) = kg::mul_u64_add::<L>(&a.limbs("a")?, a.u64("k")?, a.u64("add")?);
    ok(vec![hex_limbs(&out), format!("{carry:x}")])
}

fn div_u64<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let (q, r) = kg::div_u64::<L>(a.u64("hi")?, &a.limbs("a")?, a.u64("d")?);
    ok(vec![hex_limbs(&q), format!("{r:x}")])
}

fn inverse_of_e_mod<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&kg::inverse_of_e_mod::<L>(&a.limbs("m")?))])
}

fn gcd<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&kg::gcd::<L>(&a.limbs("a")?, &a.limbs("b")?))])
}

fn div<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&kg::div::<L>(&a.limbs("a")?, &a.limbs("d")?))])
}

fn shl<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&kg::shl::<L>(&a.limbs("a")?, a.usize("s")? as u32))])
}

fn shr<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![hex_limbs(&kg::shr::<L>(&a.limbs("a")?, a.usize("s")? as u32))])
}

fn zeros<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let x: [u64; L] = a.limbs("a")?;
    ok(vec![format!("{}", kg::trailing_zeros(&x)), format!("{}", kg::leading_zeros(&x))])
}

fn has_small_factor<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![format!("{}", kg::has_small_factor::<L>(&a.limbs("w")?) as u8)])
}

fn primes_too_close<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    ok(vec![format!("{}", kg::primes_too_close::<L>(&a.limbs("p")?, &a.limbs("q")?) as u8)])
}

fn rounds(a: &Args) -> Result<NonZeroUsize, String> {
    NonZeroUsize::new(a.usize("rounds")?).ok_or_else(|| "rounds must be nonzero".into())
}

fn is_probable_prime<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let mut rng = StreamRng::new(a.bytes("stream")?, SecurityStrength::_256bit);
    match keygen::is_probable_prime::<L, L2, L21>(&a.limbs("w")?, rounds(a)?, &mut rng) {
        Ok(v) => ok(vec![format!("{}", v as u8), format!("{}", rng.consumed())]),
        Err(e) => ok(sig_err(e)),
    }
}

fn random_prime<const L: usize, const L2: usize, const L21: usize>(a: &Args) -> Res {
    let mut rng = StreamRng::new(a.bytes("stream")?, SecurityStrength::_256bit);
    let p: Option<[u64; L]> = if a.0.contains_key("p") { Some(a.limbs("p")?) } else { None };
    let mut out = [0u64; L];
    let r = kg::random_prime::<L, L2, L21>(&mut rng, rounds(a)?, a.usize("max")?, &mut out, p.as_ref());
    match r {
        Ok(()) => ok(vec![hex_limbs(&out), format!("{}", rng.consumed())]),
        Err(e) => {
            let mut v = sig_err(e);
            v.push(hex_limbs(&out)); // the candidate buffer after a failure
            ok(v)
        }
    }
}

fn keygen_at<K, const HALF: usize, const HALF2: usize, const HALF21: usize>(a: &Args) -> Res
where
    K: RsaSigningSize + RsaSize<HalfLimbs = [u64; HALF], Limbs = [u64; HALF2]>,
{
    let mut rng = StreamRng::new(a.bytes("stream")?, strength(a.usize("strength")?)?);
    let r = keygen::keygen_from_rng::<K, HALF, HALF2, HALF21>(
        &mut rng,
        rounds(a)?,
        strength(a.usize("required")?)?,
    );
    match r {
        Ok((pk, sk)) => {
            let (p, q, dp, dq, qinv) = api::private_parts::<K>(&sk);
            ok(vec![
                hex_limbs(pk.n()),
                format!("{:x}", pk.e()),
                format!("{:x}", sk.e()),
                hex_limbs(&p),
                hex_limbs(&q),
                hex_limbs(&dp),
                hex_limbs(&dq),
                hex_limbs(&qinv),
                format!("{}", rng.consumed()),
            ])
        }
        Err(e) => ok(sig_err(e)),
    }
}

// ---------------------------------------------------------------- keys (plan I1, I2)

/// A constructor's or decoder's answer as one token: `OK`, or `ERR:` and the error as printed.
fn verdict<T, E: core::fmt::Debug>(r: &Result<T, E>) -> String {
    match r {
        Ok(_) => "OK".into(),
        Err(e) => format!("ERR:{e:?}").replace(' ', "_"),
    }
}

/// `n || e` as the crate documents it: `n` in `8 * L` big-endian bytes, `e` in eight.
fn public_encoding<const L: usize>(n: &[u64; L], e: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 * L + 8);
    for limb in n.iter().rev() {
        out.extend_from_slice(&limb.to_be_bytes());
    }
    out.extend_from_slice(&e.to_be_bytes());
    out
}

/// Every public path to a public key of size `K`, on one `(n, e)`: the components, the
/// signature key, its decoder, the key-establishment key, its decoder. Then, where the
/// signature key exists, its own encoding and whether decoding that gives the key back.
fn key_public<K, const L: usize, const PK: usize>(a: &Args) -> Res
where
    K: RsaSize<Limbs = [u64; L], PublicKeyEncoded = [u8; PK]>,
{
    let n: [u64; L] = a.limbs("n")?;
    let e = a.u64("e")?;
    let enc = public_encoding(&n, e);
    let components = RsaPublicComponents::<K>::new(&n, e);
    let key = RsaPublicKey::<RSASSA_PKCS1_v1_5<K, SHA256>>::new(&n, e);
    let decoded = <RsaPublicKey<RSASSA_PKCS1_v1_5<K, SHA256>> as PublicKey<PK>>::from_bytes(&enc);
    let kem = RsaKEMPublicKey::<K>::new(&n, e);
    let kem_decoded = <RsaKEMPublicKey<K> as PublicKey<PK>>::from_bytes(&enc);
    let (own, round_trip) = match (&key, &decoded) {
        (Ok(k), Ok(d)) => {
            let own = PublicKey::<PK>::encode(k);
            (hex_bytes(&own), format!("{}", (k == d && own[..] == enc[..]) as u8))
        }
        _ => ("-".into(), "-".into()),
    };
    ok(vec![
        verdict(&components),
        verdict(&key),
        verdict(&decoded),
        verdict(&kem),
        verdict(&kem_decoded),
        own,
        round_trip,
    ])
}

/// The same for a private key, on one `(p, q, dP, dQ, qInv, e)`, and on success `n`.
fn key_private<K, const L: usize, const HALF: usize, const SK: usize>(a: &Args) -> Res
where
    K: RsaSigningSize
        + RsaSize<Limbs = [u64; L], HalfLimbs = [u64; HALF], PrivateKeyEncoded = [u8; SK]>,
{
    let parts: [[u64; HALF]; 5] =
        [a.limbs("p")?, a.limbs("q")?, a.limbs("dp")?, a.limbs("dq")?, a.limbs("qinv")?];
    let [p, q, dp, dq, qinv] = &parts;
    let e = a.u64("e")?;
    let mut enc = Vec::with_capacity(SK);
    for part in &parts {
        for limb in part.iter().rev() {
            enc.extend_from_slice(&limb.to_be_bytes());
        }
    }
    enc.extend_from_slice(&e.to_be_bytes());
    let components = RsaPrivateComponents::<K>::from_crt_components(p, q, dp, dq, qinv, e);
    let key =
        RsaPrivateKey::<RSASSA_PKCS1_v1_5<K, SHA256>>::from_crt_components(p, q, dp, dq, qinv, e);
    let decoded = <RsaPrivateKey<RSASSA_PKCS1_v1_5<K, SHA256>> as PrivateKey<SK>>::from_bytes(&enc);
    let kem = RsaKEMPrivateKey::<K>::from_crt_components(p, q, dp, dq, qinv, e);
    let kem_decoded = <RsaKEMPrivateKey<K> as PrivateKey<SK>>::from_bytes(&enc);
    let (n, own, round_trip) = match (&key, &decoded) {
        (Ok(k), Ok(d)) => {
            let own = PrivateKey::<SK>::encode(k);
            (hex_limbs(k.n()), hex_bytes(&own), format!("{}", (k == d && own[..] == enc[..]) as u8))
        }
        _ => ("-".into(), "-".into(), "-".into()),
    };
    ok(vec![
        verdict(&components),
        verdict(&key),
        verdict(&decoded),
        verdict(&kem),
        verdict(&kem_decoded),
        n,
        own,
        round_trip,
    ])
}

// ---------------------------------------------------------------- *_from_hash (plan E11)

type V15 = RSASSA_PKCS1_v1_5<RSA2048, SHA256>;
type Pss = RSASSA_PSS<RSA2048, SHA256>;
type PssNoSalt = RSASSA_PSS<RSA2048, SHA256, NoSalt<SHA256>>;

fn components_2048(a: &Args) -> Result<RsaPrivateComponents<RSA2048>, String> {
    RsaPrivateComponents::<RSA2048>::from_crt_components(
        &a.limbs("p")?,
        &a.limbs("q")?,
        &a.limbs("dp")?,
        &a.limbs("dq")?,
        &a.limbs("qinv")?,
        a.u64("e")?,
    )
    .map_err(|e| format!("the case's key was refused: {e:?}"))
}

fn sig_out(r: Result<[u8; 256], SignatureError>) -> Vec<String> {
    match r {
        Ok(sig) => vec![hex_bytes(&sig)],
        Err(e) => sig_err(e),
    }
}

/// The four `*_from_hash` entry points at RSA-2048, each with slices of the case's lengths.
/// `sign_rng` also reports how often the RNG was called and how many bytes it gave.
fn from_hash(a: &Args) -> Res {
    let (scheme, entry) = (a.raw("scheme")?, a.raw("entry")?);
    let hash = a.bytes("hash")?;
    let sk = components_2048(a)?;
    match (scheme, entry) {
        ("v15", "sign_det") => {
            ok(sig_out(rsassa::sign_from_hash_deterministic::<V15, 256>(&sk.key(), &hash)))
        }
        ("pssns", "sign_det") => {
            ok(sig_out(rsassa::sign_from_hash_deterministic::<PssNoSalt, 256>(&sk.key(), &hash)))
        }
        ("pss", "sign_salt") => ok(sig_out(rsassa::sign_from_hash_with_salt::<Pss, 256>(
            &sk.key(),
            &hash,
            &a.bytes("salt")?,
        ))),
        ("pss", "sign_rng") => {
            let mut rng = StreamRng::new(a.bytes("stream")?, SecurityStrength::_256bit);
            let mut v = sig_out(rsassa::sign_from_hash::<Pss, 256>(&sk.key(), &hash, &mut rng));
            v.push(format!("calls={}", rng.calls()));
            v.push(format!("consumed={}", rng.consumed()));
            ok(v)
        }
        (_, "verify") => {
            let sig: [u8; 256] =
                a.bytes("sig")?.try_into().map_err(|_| "sig: 256 bytes".to_string())?;
            let pk = RsaPublicComponents::<RSA2048>::new(sk.n(), sk.e())
                .map_err(|e| format!("public half refused: {e:?}"))?;
            let r = match scheme {
                "v15" => rsassa::verify_from_hash::<V15, 256>(&pk.key(), &hash, &sig),
                "pss" => rsassa::verify_from_hash::<Pss, 256>(&pk.key(), &hash, &sig),
                "pssns" => rsassa::verify_from_hash::<PssNoSalt, 256>(&pk.key(), &hash, &sig),
                other => return Err(format!("unknown scheme {other}")),
            };
            match r {
                Ok(()) => ok(vec!["VALID".into()]),
                Err(e) => ok(sig_err(e)),
            }
        }
        other => Err(format!("unsupported (scheme, entry) {other:?}")),
    }
}

fn em_out<const K: usize>(r: Result<[u8; K], SignatureError>) -> Vec<String> {
    match r {
        Ok(em) => vec![hex_bytes(&em)],
        Err(e) => sig_err(e),
    }
}

/// `emsa_encode` and `emsa_verify` as the public algorithm traits offer them, which is the
/// second way to the encoders (finding F-03, row (b)); `pss1024_62` and `pss1024_63` are RFC
/// 8017 section 9.1.1 step 3 at its boundary, a size no private key exists at.
fn emsa(a: &Args) -> Res {
    type P1024<const S: usize> = RSASSA_PSS<RSA1024, SHA512, Mgf1<SHA512, S>>;
    let hash = a.bytes("hash")?;
    let salt = || a.bytes("salt");
    let em = |k: usize| -> Result<Vec<u8>, String> {
        let em = a.bytes("em")?;
        if em.len() == k { Ok(em) } else { Err(format!("em: {k} bytes")) }
    };
    let b = |v: bool| ok(vec![format!("{}", v as u8)]);
    match (a.raw("scheme")?, a.raw("entry")?) {
        ("v15", "encode") => ok(em_out(V15::emsa_encode::<256>(&hash))),
        ("pssns", "encode") => ok(em_out(PssNoSalt::emsa_encode::<256>(&hash))),
        ("pss", "encode") => ok(em_out(Pss::emsa_encode::<256>(&hash, &salt()?))),
        ("pss1024_62", "encode") => ok(em_out(P1024::<62>::emsa_encode::<128>(&hash, &salt()?))),
        ("pss1024_63", "encode") => ok(em_out(P1024::<63>::emsa_encode::<128>(&hash, &salt()?))),
        ("v15", "verify") => b(V15::emsa_verify::<256>(&hash, &em(256)?.try_into().unwrap())),
        ("pssns", "verify") => b(PssNoSalt::emsa_verify::<256>(&hash, &em(256)?.try_into().unwrap())),
        ("pss", "verify") => b(Pss::emsa_verify::<256>(&hash, &em(256)?.try_into().unwrap())),
        ("pss1024_62", "verify") => {
            b(P1024::<62>::emsa_verify::<128>(&hash, &em(128)?.try_into().unwrap()))
        }
        ("pss1024_63", "verify") => {
            b(P1024::<63>::emsa_verify::<128>(&hash, &em(128)?.try_into().unwrap()))
        }
        other => Err(format!("unsupported (scheme, entry) {other:?}")),
    }
}

// ---------------------------------------------------------------- fill_bytes (plan K16)

/// `fill_bytes` against an RNG that fills the buffer and then claims `claim` bytes (`err`: its
/// own error). Reports the result, the calls made, and whether the buffer is all zero.
fn fill_bytes(a: &Args) -> Res {
    let len = a.usize("len")?;
    let claim = match a.raw("claim")? {
        "err" => None,
        n => Some(n.parse::<usize>().map_err(|e| format!("claim: {e}"))?),
    };
    let mut rng = ShortRng { fill: 0xA5, claim, calls: 0 };
    let mut buf = vec![0x5Au8; len];
    let r = kg::fill_bytes(&mut rng, &mut buf);
    let state = if buf.iter().all(|&b| b == 0) {
        "zero"
    } else if buf.iter().all(|&b| b == 0xA5) {
        "filled"
    } else {
        "other"
    };
    let mut v = match r {
        Ok(()) => vec!["FILLED".to_string()],
        Err(e) => vec!["ERR".into(), format!("{e:?}").replace(' ', "_")],
    };
    v.push(format!("calls={}", rng.calls));
    v.push(format!("buf={state}"));
    ok(v)
}

// ---------------------------------------------------------------- dispatch

macro_rules! by_l {
    ($l:expr, $f:ident, $a:expr) => {
        match $l {
            1 => $f::<1, 2, 3>($a),
            2 => $f::<2, 4, 5>($a),
            3 => $f::<3, 6, 7>($a),
            4 => $f::<4, 8, 9>($a),
            8 => $f::<8, 16, 17>($a),
            16 => $f::<16, 32, 33>($a),
            24 => $f::<24, 48, 49>($a),
            32 => $f::<32, 64, 65>($a),
            48 => $f::<48, 96, 97>($a),
            64 => $f::<64, 128, 129>($a),
            128 => $f::<128, 256, 257>($a),
            other => Err(format!("unsupported L = {other}")),
        }
    };
}

fn run(op: &str, a: &Args) -> Res {
    let l = || a.usize("L");
    match op {
        "nat_add" => by_l!(l()?, nat_add, a),
        "nat_sub" => by_l!(l()?, nat_sub, a),
        "nat_add_assign" => by_l!(l()?, nat_add_assign, a),
        "nat_sub_assign" => by_l!(l()?, nat_sub_assign, a),
        "nat_is_zero" => by_l!(l()?, nat_is_zero, a),
        "widening_mul" => by_l!(l()?, widening_mul, a),
        "widening_mul_into" => by_l!(l()?, widening_mul_into, a),
        "widening_square" => by_l!(l()?, widening_square, a),
        "redc" => by_l!(l()?, redc, a),
        "mont_n_prime" => ok(vec![format!("{:016x}", modexp::mont_n_prime(a.u64("n0")?))]),
        "ctx_public" => by_l!(l()?, ctx_public, a),
        "ctx_secret" => by_l!(l()?, ctx_secret, a),
        "double_mod_n_vartime" => by_l!(l()?, double_mod_n_vartime, a),
        "pow2_mod_vartime" => by_l!(l()?, pow2_mod_vartime, a),
        "pow2_ct" => by_l!(l()?, pow2_ct, a),
        "pow2_trace" => by_l!(l()?, pow2_trace, a),
        "redc_normalize" => by_l!(l()?, redc_normalize, a),
        "mont_mul" => by_l!(l()?, mont_mul, a),
        "mont_square" => by_l!(l()?, mont_square, a),
        "to_montgomery" => by_l!(l()?, to_montgomery, a),
        "from_montgomery" => by_l!(l()?, from_montgomery, a),
        "mul_mod" => by_l!(l()?, mul_mod, a),
        "sub_mod" => by_l!(l()?, sub_mod, a),
        "ct_shift_in_bit_mod" => by_l!(l()?, ct_shift_in_bit_mod, a),
        "ct_select_array" => by_l!(l()?, ct_select_array, a),
        "ct_swap_array" => by_l!(l()?, ct_swap_array, a),
        "mod_pow" => by_l!(l()?, mod_pow, a),
        "mod_pow_public_exponent" => by_l!(l()?, mod_pow_public_exponent, a),
        "public_exp" => by_l!(l()?, public_exp, a),
        "reduce_wide" => match (a.usize("WIDE")?, a.usize("NARROW")?) {
            (1, 1) => reduce_wide::<1, 1>(a),
            (2, 1) => reduce_wide::<2, 1>(a),
            (3, 1) => reduce_wide::<3, 1>(a),
            (1, 2) => reduce_wide::<1, 2>(a),
            (2, 2) => reduce_wide::<2, 2>(a),
            (4, 2) => reduce_wide::<4, 2>(a),
            (4, 3) => reduce_wide::<4, 3>(a),
            (1, 4) => reduce_wide::<1, 4>(a),
            (4, 4) => reduce_wide::<4, 4>(a),
            (8, 4) => reduce_wide::<8, 4>(a),
            (8, 8) => reduce_wide::<8, 8>(a),
            (16, 8) => reduce_wide::<16, 8>(a),
            (16, 16) => reduce_wide::<16, 16>(a),
            (32, 16) => reduce_wide::<32, 16>(a),
            (24, 24) => reduce_wide::<24, 24>(a),
            (48, 24) => reduce_wide::<48, 24>(a),
            (32, 32) => reduce_wide::<32, 32>(a),
            (64, 32) => reduce_wide::<64, 32>(a),
            (64, 64) => reduce_wide::<64, 64>(a),
            (128, 64) => reduce_wide::<128, 64>(a),
            other => Err(format!("unsupported reduce_wide widths {other:?}")),
        },
        "crt_exp" => match a.usize("HALF")? {
            1 => crt_exp::<2, 4, 5, 1, 2, 3>(a),
            2 => crt_exp::<4, 8, 9, 2, 4, 5>(a),
            4 => crt_exp::<8, 16, 17, 4, 8, 9>(a),
            8 => crt_exp::<16, 32, 33, 8, 16, 17>(a),
            16 => crt_exp::<32, 64, 65, 16, 32, 33>(a),
            24 => crt_exp::<48, 96, 97, 24, 48, 49>(a),
            32 => crt_exp::<64, 128, 129, 32, 64, 65>(a),
            64 => crt_exp::<128, 256, 257, 64, 128, 129>(a),
            other => Err(format!("unsupported HALF = {other}")),
        },
        "crt_exp_checked" => match a.usize("HALF")? {
            1 => crt_exp_checked::<2, 4, 5, 1, 2, 3>(a),
            2 => crt_exp_checked::<4, 8, 9, 2, 4, 5>(a),
            4 => crt_exp_checked::<8, 16, 17, 4, 8, 9>(a),
            8 => crt_exp_checked::<16, 32, 33, 8, 16, 17>(a),
            16 => crt_exp_checked::<32, 64, 65, 16, 32, 33>(a),
            24 => crt_exp_checked::<48, 96, 97, 24, 48, 49>(a),
            32 => crt_exp_checked::<64, 128, 129, 32, 64, 65>(a),
            64 => crt_exp_checked::<128, 256, 257, 64, 128, 129>(a),
            other => Err(format!("unsupported HALF = {other}")),
        },
        "key_public" => match a.usize("BITS")? {
            1024 => key_public::<RSA1024, 16, 136>(a),
            1536 => key_public::<RSA1536, 24, 200>(a),
            2048 => key_public::<RSA2048, 32, 264>(a),
            3072 => key_public::<RSA3072, 48, 392>(a),
            4096 => key_public::<RSA4096, 64, 520>(a),
            8192 => key_public::<RSA8192, 128, 1032>(a),
            other => Err(format!("no size of {other} bits")),
        },
        "key_private" => match a.usize("BITS")? {
            2048 => key_private::<RSA2048, 32, 16, 648>(a),
            3072 => key_private::<RSA3072, 48, 24, 968>(a),
            4096 => key_private::<RSA4096, 64, 32, 1288>(a),
            8192 => key_private::<RSA8192, 128, 64, 2568>(a),
            other => Err(format!("no private key at {other} bits")),
        },
        "from_hash" => from_hash(a),
        "emsa" => emsa(a),
        "fill_bytes" => fill_bytes(a),
        "codec" => match l()? {
            1 => codec_round_trip::<1, 8>(a),
            2 => codec_round_trip::<2, 16>(a),
            4 => codec_round_trip::<4, 32>(a),
            16 => codec_round_trip::<16, 128>(a),
            32 => codec_round_trip::<32, 256>(a),
            128 => codec_round_trip::<128, 1024>(a),
            other => Err(format!("unsupported codec L = {other}")),
        },
        "mod_u64" => by_l!(l()?, mod_u64, a),
        "mul_u64_add" => by_l!(l()?, mul_u64_add, a),
        "div_u64" => by_l!(l()?, div_u64, a),
        "inv_mod_u64_prime" => {
            ok(vec![format!("{:x}", kg::inv_mod_u64_prime(a.u64("r")?, a.u64("e")?))])
        }
        "inverse_of_e_mod" => by_l!(l()?, inverse_of_e_mod, a),
        "gcd" => by_l!(l()?, gcd, a),
        "div" => by_l!(l()?, div, a),
        "shl" => by_l!(l()?, shl, a),
        "shr" => by_l!(l()?, shr, a),
        "zeros" => by_l!(l()?, zeros, a),
        "has_small_factor" => by_l!(l()?, has_small_factor, a),
        "primes_too_close" => by_l!(l()?, primes_too_close, a),
        "is_probable_prime" => by_l!(l()?, is_probable_prime, a),
        "random_prime" => by_l!(l()?, random_prime, a),
        "keygen" => match a.usize("HALF")? {
            16 => keygen_at::<RSA2048, 16, 32, 33>(a),
            24 => keygen_at::<RSA3072, 24, 48, 49>(a),
            32 => keygen_at::<RSA4096, 32, 64, 65>(a),
            64 => keygen_at::<RSA8192, 64, 128, 129>(a),
            other => Err(format!("keygen exists at HALF in 16, 24, 32, 64; got {other}")),
        },
        other => Err(format!("unknown op {other}")),
    }
}

fn main() {
    // Panics are results here; keep them off stderr.
    std::panic::set_hook(Box::new(|_| {}));
    let worker = std::thread::Builder::new().stack_size(256 << 20).spawn(|| {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut out = std::io::BufWriter::new(stdout.lock());
        let mut harness_errors = 0usize;
        for line in stdin.lock().lines() {
            let line = line.expect("read");
            let mut it = line.split_whitespace();
            let (Some(id), Some(op)) = (it.next(), it.next()) else { continue };
            if id.starts_with('#') {
                continue;
            }
            let args = Args(it.filter_map(|kv| kv.split_once('=')).collect());
            let result = catch_unwind(AssertUnwindSafe(|| run(op, &args)));
            match result {
                Ok(Ok(v)) if v.first().map(String::as_str) == Some("ERR") => {
                    writeln!(out, "{id} {}", v.join(" ")).unwrap()
                }
                Ok(Ok(v)) => writeln!(out, "{id} OK {}", v.join(" ")).unwrap(),
                Ok(Err(e)) => {
                    harness_errors += 1;
                    writeln!(out, "{id} HARNESS {}", e.replace(' ', "_")).unwrap()
                }
                Err(payload) => {
                    let msg = payload
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "non-string panic".into());
                    writeln!(out, "{id} PANIC {}", msg.replace(['\n', ' '], "_")).unwrap()
                }
            }
        }
        out.flush().unwrap();
        harness_errors
    });
    let harness_errors = worker.expect("spawn").join().expect("runner thread");
    if harness_errors > 0 {
        eprintln!("{harness_errors} case(s) could not be run (HARNESS lines)");
        std::process::exit(2);
    }
}
