//! Secret-independence of the private-key path, checked with Valgrind memcheck (plan section
//! 5.5 step 2), in the pattern of upstream's `dev_scripts/oaep_ct_harness`: the secret inputs
//! are made *undefined* in memcheck's eyes, and memcheck then reports every conditional jump
//! and every address that depends on them.
//!
//!     valgrind -q target/memcheck/ct_memcheck MODE BITS P Q DP DQ QINV
//!     target/memcheck/ct_memcheck genkey BITS         (natively: prints P Q DP DQ QINV)
//!
//! BITS is 2048, 3072, 4096 or 8192; the five key components are hex, 16 digits to a limb.
//! `check_ct_memcheck.sh` supplies them, reads memcheck's report and holds the expected verdict
//! of each mode.
//!
//! A secret keeps its value: it is XORed with two reads of a word of never-written heap memory,
//! which is zero in effect and undefined to memcheck. Every mode ends by running [`control`], a
//! deliberately variable-time scan, over the very values it handed to the code under test.
//! memcheck must report that scan: a run in which it does not is void, because the inputs
//! were then not undefined and a silent memcheck proves nothing. (The first version of this
//! file read the word through a plain reference; the compiler, entitled to treat
//! uninitialised memory as any value, passed a stale register on some paths and the taint
//! vanished there. The pointer goes through `black_box` and is read volatile.)
//!
//! Three kinds of mode since the port to `30cbbab` (WP14.3):
//!
//! * the constructors: `ctx_secret`, which must be clean, and `ctx_public`, which must be
//!   reported -- the variable-time form over the same undefined modulus, a control on the
//!   code beside each mode's control on its inputs;
//! * the kernel: the checked CRT with the key undefined (`crt_key`) or the base (`crt_base`),
//!   the unchecked CRT (`crt_raw_key`), the public exponentiation over an undefined base
//!   (`public_exp_base`), and the pieces `mod_pow`, `reduce_wide`, `sub_mod`, `mul_mod`,
//!   `recombine`, each with every input undefined;
//! * whole operations through the public API, with the key's five secret components made
//!   undefined inside the key object and `n`, `e` left defined: `sign` (PKCS #1 v1.5),
//!   `sign_pss`, `rsasve_recover`, `oaep_decrypt` (a ciphertext made for the key) and
//!   `oaep_decrypt_bad` (a ciphertext that does not decode). These are not expected to be
//!   silent: the outcome of the result check is branched on by design. The script judges them
//!   against the declassification register (plan section 5.5 step 1).
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::kem_key::DecapsulatingKey;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::key_transport_key::{KeyTransportDecryptingKey, KeyTransportEncryptingKey};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_ec::{montgomery, nat};
use bouncycastle_sha2::SHA256;
use rsa_audit_harness::api;
use rsa_audit_harness::keys::{RsaPrivateComponents, RsaPrivateKey};
use rsa_audit_harness::modexp::{self, MontgomeryContext, probe};
use rsa_audit_harness::rsaes_oaep::OaepParams;
use rsa_audit_harness::rsassa;
use rsa_audit_harness::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use rsa_audit_harness::rsassa_pss::RSASSA_PSS;
use rsa_audit_harness::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey};
use rsa_audit_harness::size::{RsaSigningSize, RsaSize};
use rsa_audit_harness::{RSA2048, RSA3072, RSA4096, RSA8192};
use std::alloc::{Layout, alloc};
use std::hint::black_box;

fn parse<const N: usize>(s: &str) -> [u64; N] {
    assert_eq!(s.len(), 16 * N, "expected {} hex digits", 16 * N);
    let mut out = [0u64; N];
    for i in 0..N {
        out[i] = u64::from_str_radix(&s[16 * (N - 1 - i)..16 * (N - i)], 16).expect("hex");
    }
    out
}

fn hex(a: &[u64]) -> String {
    a.iter().rev().map(|l| format!("{l:016x}")).collect()
}

/// A pointer to one word memcheck regards as undefined.
fn undefined_word() -> *const u64 {
    let layout = Layout::new::<u64>();
    // SAFETY: a fresh allocation, deliberately left uninitialised and never freed. This
    // program exists only to be run under memcheck, which tracks the word as undefined.
    // `black_box` hides from the compiler that nothing was ever written there.
    let p = black_box(unsafe { alloc(layout) }) as *const u64;
    assert!(!p.is_null());
    p
}

/// `x`, with every bit undefined to memcheck: the two volatile reads cancel, but an XOR with
/// an undefined operand is undefined.
#[inline(never)]
fn taint<const N: usize>(x: &[u64; N], u: *const u64) -> [u64; N] {
    let mut out = [0u64; N];
    for i in 0..N {
        // SAFETY: `u` is the live allocation from `undefined_word`; see there.
        let (a, b) = unsafe { (core::ptr::read_volatile(u), core::ptr::read_volatile(u)) };
        out[i] = x[i] ^ a ^ b;
    }
    out
}

/// Makes each of `parts` undefined where it lies inside `key`, value unchanged. The key types
/// give no mutable access to their components, so each is found by its limbs in the key's
/// bytes, as upstream's `rsa_ct_harness` does; it must be found exactly once. What is not
/// named -- `n` and `e` -- stays defined: the result check works over those two in variable
/// time, as it may.
///
/// # Safety
/// `T` must be a key type of this crate: plain limb arrays and a `u64`, no padding, no
/// pointers. Nothing else may borrow `key` during the call.
#[inline(never)]
unsafe fn taint_in_place<T>(key: &mut T, parts: &[&[u64]], u: *const u64) {
    let size = size_of::<T>();
    let base = (key as *mut T).cast::<u8>();
    // SAFETY: `base` points at `size` initialised bytes of `key` (the caller's contract).
    let image = unsafe { std::slice::from_raw_parts(base, size) }.to_vec();
    for part in parts {
        let needle: Vec<u8> = part.iter().flat_map(|limb| limb.to_ne_bytes()).collect();
        let hits: Vec<usize> = image
            .windows(needle.len())
            .enumerate()
            .filter(|(_, w)| *w == needle.as_slice())
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits.len(), 1, "a component was found {} times in the key", hits.len());
        for w in 0..part.len() {
            // SAFETY: within the key, at a limb of the component just found; `u` as in `taint`.
            unsafe {
                let at = base.add(hits[0] + 8 * w).cast::<u64>();
                let (a, b) = (core::ptr::read_volatile(u), core::ptr::read_volatile(u));
                at.write_unaligned(at.read_unaligned() ^ a ^ b);
            }
        }
    }
}

/// A scan whose running time depends on its input: memcheck must report it.
#[inline(never)]
fn control<const N: usize>(a: &[u64; N]) -> usize {
    let mut i = 0;
    while i < N && a[i] != 0 {
        i += 1;
    }
    i
}

/// xorshift64*: an endless deterministic stream, for `genkey` and for the OAEP seed.
struct XorShift(u64);

impl RNG for XorShift {
    fn add_seed_keymaterial(&mut self, _seed: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Ok(())
    }

    fn next_int(&mut self) -> Result<u32, RNGError> {
        let mut b = [0u8; 4];
        self.next_bytes_out(&mut b)?;
        Ok(u32::from_be_bytes(b))
    }

    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        for chunk in out.chunks_mut(8) {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            let word = self.0.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(out.len())
    }

    fn fill_keymaterial_out(&mut self, _out: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("audit xorshift RNG does not fill key material"))
    }

    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

macro_rules! at_size {
    ($name:ident, $K:ty, $L:literal, $L2:literal, $L21:literal, $H:literal, $H2:literal, $H21:literal, $KLEN:literal) => {
        fn $name(mode: &str, args: &[String]) {
            const L: usize = $L;
            const HALF: usize = $H;
            type V15 = RSASSA_PKCS1_v1_5<$K, SHA256>;
            type Pss = RSASSA_PSS<$K, SHA256>;

            if mode == "genkey" {
                let (_, sk) = <$K as RsaSigningSize>::keygen(&mut XorShift(0x5eed_0000 + $L))
                    .expect("key generation");
                let (p, q, dp, dq, qinv) = api::private_parts::<$K>(&sk);
                // The key is sound in the sense the harness needs: its result check passes.
                let mut x = [0x0123_4567_89ab_cdefu64; L];
                x[L - 1] = 1;
                let mut out = [0u64; L];
                assert!(api::crt_exp_checked::<$L, $L2, $L21, $H, $H2, $H21>(
                    &p, &q, &dp, &dq, &qinv, sk.n(), sk.e(), &x, &mut out
                ));
                println!("{} {} {} {} {}", hex(&p), hex(&q), hex(&dp), hex(&dq), hex(&qinv));
                return;
            }

            assert_eq!(args.len(), 5, "usage: ct_memcheck MODE BITS P Q DP DQ QINV");
            let (p, q): ([u64; HALF], [u64; HALF]) = (parse(&args[0]), parse(&args[1]));
            let (dp, dq, qinv): ([u64; HALF], [u64; HALF], [u64; HALF]) =
                (parse(&args[2]), parse(&args[3]), parse(&args[4]));
            let e = 65537u64;
            let n: [u64; L] = montgomery::widening_mul::<HALF, L>(&p, &q);
            let u = undefined_word();
            // A public message representative below n (n's top bit is set, this one's is not),
            // and a context over p built from defined values.
            let mut m = [0x0123_4567_89ab_cdefu64; L];
            m[L - 1] = 1;
            let ctx_p = MontgomeryContext::<HALF>::for_secret_modulus(&p);
            let (cm, cnp, cr, cr2) = probe::ctx_fields(&ctx_p);
            let mut small = [0u64; HALF];
            small.copy_from_slice(&m[..HALF]);
            small[HALF - 1] = 0; // below p, whose top bit is set

            // The tainted values. Each mode uses some of them and then scans the ones it used.
            let (tp, tq) = (taint(&p, u), taint(&q, u));
            let (tdp, tdq, tqinv) = (taint(&dp, u), taint(&dq, u), taint(&qinv, u));
            let (tm, tsmall) = (taint(&m, u), taint(&small, u));
            let tctx = probe::ctx_from_fields(
                taint(&cm, u),
                taint(&[cnp], u)[0],
                taint(&cr, u),
                taint(&cr2, u),
            );
            let parts: [&[u64]; 5] = [&p, &q, &dp, &dq, &qinv];

            match mode {
                // Nothing but the scan: shows what a report of it looks like.
                "control" => {}
                // Context construction over a secret modulus: finding F-01. Clean since 04305e0.
                "ctx_secret" => {
                    black_box(MontgomeryContext::<HALF>::for_secret_modulus(&tp));
                    black_box(control(&tp));
                }
                // The variable-time constructor over the same modulus: must be reported.
                "ctx_public" => {
                    black_box(MontgomeryContext::<HALF>::for_public_modulus(&tp));
                    black_box(control(&tp));
                }
                // The checked CRT: both exponentiations, the recombination, the public
                // exponentiation of the result, the comparison and the masked write. Key
                // undefined, input and (n, e) defined. The verdict is taken as a word, not
                // branched on.
                "crt_key" => {
                    let mut out = [0u64; L];
                    black_box(api::crt_exp_checked_word::<$L, $L2, $L21, $H, $H2, $H21>(
                        &tp, &tq, &tdp, &tdq, &tqinv, &n, e, &m, &mut out,
                    ));
                    black_box(&out);
                    black_box((control(&tp), control(&tq), control(&tdp), control(&tdq), control(&tqinv)));
                }
                // The same with the key defined and only the input undefined.
                "crt_base" => {
                    let mut out = [0u64; L];
                    black_box(api::crt_exp_checked_word::<$L, $L2, $L21, $H, $H2, $H21>(
                        &p, &q, &dp, &dq, &qinv, &n, e, &tm, &mut out,
                    ));
                    black_box(&out);
                    black_box(control(&tm));
                }
                // The CRT without its check, as the first pass ran it.
                "crt_raw_key" => {
                    black_box(api::crt_exp::<$L, $L2, $L21, $H, $H2, $H21>(&tp, &tq, &tdp, &tdq, &tqinv, &m));
                    black_box((control(&tp), control(&tq), control(&tdp), control(&tdq), control(&tqinv)));
                }
                // The pieces of the CRT after its contexts exist, each with every input secret.
                "mod_pow" => {
                    black_box(modexp::mod_pow::<$H, $H2, $H21>(&tsmall, &tdp, &tctx));
                    let (fm, fnp, fr, fr2) = probe::ctx_fields(&tctx);
                    black_box((control(&tsmall), control(&tdp), control(&fm), control(&[fnp]), control(&fr), control(&fr2)));
                }
                "reduce_wide" => {
                    black_box(modexp::reduce_wide::<L, HALF>(&tm, &tp));
                    black_box(modexp::reduce_wide::<HALF, HALF>(&tsmall, &tp));
                    black_box((control(&tm), control(&tsmall), control(&tp)));
                }
                "sub_mod" => {
                    black_box(modexp::sub_mod::<HALF>(&tsmall, &tqinv, &tp));
                    black_box((control(&tsmall), control(&tqinv), control(&tp)));
                }
                "mul_mod" => {
                    black_box(modexp::mul_mod::<$H, $H2, $H21>(&tsmall, &tqinv, &tctx));
                    let (fm, ..) = probe::ctx_fields(&tctx);
                    black_box((control(&tsmall), control(&tqinv), control(&fm)));
                }
                "recombine" => {
                    let t: [u64; L] = montgomery::widening_mul::<HALF, L>(&tq, &tsmall);
                    let mut wide = [0u64; L];
                    wide[..HALF].copy_from_slice(&tsmall);
                    black_box(nat::add(&wide, &t));
                    black_box((control(&tq), control(&tsmall)));
                }
                // The public-key operation on a secret base (RSASVE's z, an unreleased CRT
                // result), modulus and exponent public: plan M11.
                "public_exp_base" => {
                    black_box(api::public_exp::<$L, $L2, $L21>(&n, e, &tm));
                    black_box(control(&tm));
                }
                // Whole operations. The key is built from defined values, since construction
                // validates in variable time and says so, and its secret components are made
                // undefined where they lie. Results are not inspected: whether an operation
                // succeeded is computed from the key, and a branch on it here would be this
                // program's own.
                "sign" | "sign_pss" => {
                    let components =
                        RsaPrivateComponents::<$K>::from_crt_components(&p, &q, &dp, &dq, &qinv, e)
                            .expect("a sound key");
                    let digest = [0x3cu8; 32];
                    if mode == "sign" {
                        let mut key: RsaPrivateKey<V15> = components.into_key();
                        // SAFETY: a key type of the crate; nothing else borrows it.
                        unsafe { taint_in_place(&mut key, &parts, u) };
                        black_box(&rsassa::sign_from_hash_deterministic::<V15, $KLEN>(&key, &digest));
                        let (kp, kq, kdp, kdq, kqinv) = api::private_parts::<$K>(key.components());
                        black_box((control(&kp), control(&kq), control(&kdp), control(&kdq), control(&kqinv)));
                    } else {
                        let mut key: RsaPrivateKey<Pss> = components.into_key();
                        // SAFETY: as above.
                        unsafe { taint_in_place(&mut key, &parts, u) };
                        black_box(&rsassa::sign_from_hash_with_salt::<Pss, $KLEN>(&key, &digest, &[0x71u8; 32]));
                        let (kp, kq, kdp, kdq, kqinv) = api::private_parts::<$K>(key.components());
                        black_box((control(&kp), control(&kq), control(&kdp), control(&kdq), control(&kqinv)));
                    }
                }
                "rsasve_recover" => {
                    let mut key =
                        RsaKEMPrivateKey::<$K>::from_crt_components(&p, &q, &dp, &dq, &qinv, e)
                            .expect("a sound key");
                    // SAFETY: as above.
                    unsafe { taint_in_place(&mut key, &parts, u) };
                    // Any c with 1 < c < n - 1 is a ciphertext: RSASVE has no redundancy.
                    let ct: [u8; $KLEN] = <$K as RsaSize>::be_bytes_from_limbs(&m);
                    let mut ss = KeyMaterial::<$KLEN>::new();
                    black_box(&key.decaps_out(&ct, (), &mut ss));
                    black_box(&ss);
                    let (kp, kq, kdp, kdq, kqinv) = api::private_parts::<$K>(api::kem_components(&key));
                    black_box((control(&kp), control(&kq), control(&kdp), control(&kdq), control(&kqinv)));
                }
                "oaep_decrypt" | "oaep_decrypt_bad" => {
                    let params = OaepParams::<SHA256>::new(b"audit");
                    let pk = RsaKEMPublicKey::<$K>::new(&n, e).expect("the public half");
                    let transported =
                        KeyMaterial::<32>::from_bytes_as_type(&[0x42u8; 32], KeyType::MACKey)
                            .expect("32 bytes of key");
                    let mut ct: [u8; $KLEN] = pk
                        .transport(&mut XorShift(0x0aeb), params, &transported)
                        .expect("encryption under the public key");
                    if mode == "oaep_decrypt_bad" {
                        ct[$KLEN - 1] ^= 1; // another c in range: it decrypts to no encoding
                    }
                    let mut key =
                        RsaKEMPrivateKey::<$K>::from_crt_components(&p, &q, &dp, &dq, &qinv, e)
                            .expect("a sound key");
                    // SAFETY: as above.
                    unsafe { taint_in_place(&mut key, &parts, u) };
                    let mut recovered = KeyMaterial::<64>::new();
                    black_box(&key.recover_out(&ct, params, &mut recovered));
                    black_box(&recovered);
                    let (kp, kq, kdp, kdq, kqinv) = api::private_parts::<$K>(api::kem_components(&key));
                    black_box((control(&kp), control(&kq), control(&kdp), control(&kdq), control(&kqinv)));
                }
                other => panic!("unknown mode {other}"),
            }
            // Every mode: the scan over a tainted array must be reported, or the run is void.
            black_box(control(&tp));
        }
    };
}

at_size!(at_2048, RSA2048, 32, 64, 65, 16, 32, 33, 256);
at_size!(at_3072, RSA3072, 48, 96, 97, 24, 48, 49, 384);
at_size!(at_4096, RSA4096, 64, 128, 129, 32, 64, 65, 512);
at_size!(at_8192, RSA8192, 128, 256, 257, 64, 128, 129, 1024);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() >= 3, "usage: ct_memcheck MODE BITS [P Q DP DQ QINV]");
    // The frames of an RSA-8192 operation and this function's own arrays are large.
    let worker = std::thread::Builder::new().stack_size(64 << 20).spawn(move || {
        let (mode, rest) = (args[1].as_str(), &args[3..]);
        match args[2].as_str() {
            "2048" => at_2048(mode, rest),
            "3072" => at_3072(mode, rest),
            "4096" => at_4096(mode, rest),
            "8192" => at_8192(mode, rest),
            other => panic!("no signing size of {other} bits"),
        }
    });
    worker.expect("spawn").join().expect("worker");
}
