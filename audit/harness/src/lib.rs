//! Audit harness: `crypto/rsa/src/*.rs` compiled by path and unmodified, so that the functions
//! the crate keeps private can be called from differential tests against `audit/ref/rsa_ref.py`.
//! Nothing upstream changes visibility for this.
//!
//! * A file whose crate-private (`pub(crate)`) items are enough is a `#[path]` module, as
//!   `dev_scripts/oaep_ct_harness` does it. Being modules of this crate under their upstream
//!   names, the files' own `crate::...` paths resolve to each other and no stub is needed.
//! * Three files have fully private functions under test. They are included from the copies
//!   `build.rs` makes (header doc comments turned into plain comments, nothing else), inside a
//!   module that also holds a `probe` child: a child module sees its parent's private items.
//! * [`api`] re-exports what a `pub(crate)` item hides from this crate's binaries and tests.
//!
//! `build.rs` refuses to build if any included file differs from `audit/baseline.sha256`.
#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(clippy::all)]
#![allow(rustdoc::all)]

#[path = "../../../crypto/rsa/src/codec.rs"]
pub mod codec;
#[path = "../../../crypto/rsa/src/eme_oaep.rs"]
pub mod eme_oaep;
#[path = "../../../crypto/rsa/src/emsa_pss.rs"]
pub mod emsa_pss;
#[path = "../../../crypto/rsa/src/keys.rs"]
pub mod keys;
#[path = "../../../crypto/rsa/src/mgf1.rs"]
pub mod mgf1;
#[path = "../../../crypto/rsa/src/rsa_1024.rs"]
pub mod rsa_1024;
#[path = "../../../crypto/rsa/src/rsa_1536.rs"]
pub mod rsa_1536;
#[path = "../../../crypto/rsa/src/rsa_2048.rs"]
pub mod rsa_2048;
#[path = "../../../crypto/rsa/src/rsa_3072.rs"]
pub mod rsa_3072;
#[path = "../../../crypto/rsa/src/rsa_4096.rs"]
pub mod rsa_4096;
#[path = "../../../crypto/rsa/src/rsa_8192.rs"]
pub mod rsa_8192;
#[path = "../../../crypto/rsa/src/rsa_core.rs"]
pub mod rsa_core;
#[path = "../../../crypto/rsa/src/rsaes_oaep.rs"]
pub mod rsaes_oaep;
#[path = "../../../crypto/rsa/src/rsassa.rs"]
pub mod rsassa;
#[path = "../../../crypto/rsa/src/rsassa_pkcs1_v1_5.rs"]
pub mod rsassa_pkcs1_v1_5;
#[path = "../../../crypto/rsa/src/rsassa_pss.rs"]
pub mod rsassa_pss;
#[path = "../../../crypto/rsa/src/rsasve.rs"]
pub mod rsasve;
#[path = "../../../crypto/rsa/src/rsasve_kdf.rs"]
pub mod rsasve_kdf;
#[path = "../../../crypto/rsa/src/size.rs"]
pub mod size;

pub use size::{RSA1024, RSA1536, RSA2048, RSA3072, RSA4096, RSA8192};

/// `crypto/rsa/src/modexp.rs` with a probe onto its private functions.
pub mod modexp {
    include!(concat!(env!("OUT_DIR"), "/modexp.rs"));

    /// The private functions and fields of `modexp`, by their own names.
    pub mod probe {
        use super::MontgomeryContext;
        use bouncycastle_utils::ct::Condition;

        /// `check_widths`, callable in a `const` block of the caller's own.
        pub const fn check_widths<const L: usize, const L2: usize, const L21: usize>() {
            super::check_widths::<L, L2, L21>()
        }

        pub fn double_mod_n_vartime<const L: usize>(a: &[u64; L], n: &[u64; L]) -> [u64; L] {
            super::double_mod_n_vartime(a, n)
        }

        pub fn pow2_mod_vartime<const L: usize>(bits: u32, n: &[u64; L]) -> [u64; L] {
            super::pow2_mod_vartime(bits, n)
        }

        pub fn pow2_mod_ct<const L: usize>(bits: u32, n: &[u64; L]) -> [u64; L] {
            super::pow2_mod_ct(bits, n)
        }

        pub fn ct_select_array<const L: usize>(
            mask: bool,
            a: &[u64; L],
            b: &[u64; L],
        ) -> [u64; L] {
            super::ct_select_array(Condition::<u64>::from_lsb(mask as u64), a, b)
        }

        pub fn ct_swap_array<const L: usize>(mask: bool, a: &mut [u64; L], b: &mut [u64; L]) {
            super::ct_swap_array(Condition::<u64>::from_lsb(mask as u64), a, b)
        }

        pub fn redc_normalize<const L: usize, const L2: usize, const L21: usize>(
            t: &[u64; L2],
            modulus: &[u64; L],
            n_prime: u64,
        ) -> [u64; L] {
            super::redc_normalize::<L, L2, L21>(t, modulus, n_prime)
        }

        pub fn mont_mul<const L: usize, const L2: usize, const L21: usize>(
            a: &[u64; L],
            b: &[u64; L],
            modulus: &[u64; L],
            n_prime: u64,
        ) -> [u64; L] {
            super::mont_mul::<L, L2, L21>(a, b, modulus, n_prime)
        }

        pub fn mont_square<const L: usize, const L2: usize, const L21: usize>(
            a: &[u64; L],
            modulus: &[u64; L],
            n_prime: u64,
        ) -> [u64; L] {
            super::mont_square::<L, L2, L21>(a, modulus, n_prime)
        }

        pub fn to_montgomery<const L: usize, const L2: usize, const L21: usize>(
            a: &[u64; L],
            ctx: &MontgomeryContext<L>,
        ) -> [u64; L] {
            super::to_montgomery::<L, L2, L21>(a, ctx)
        }

        pub fn from_montgomery<const L: usize, const L2: usize, const L21: usize>(
            a_bar: &[u64; L],
            ctx: &MontgomeryContext<L>,
        ) -> [u64; L] {
            super::from_montgomery::<L, L2, L21>(a_bar, ctx)
        }

        pub fn ct_shift_in_bit_mod<const N: usize>(
            acc: &[u64; N],
            bit: u64,
            modulus: &[u64; N],
        ) -> [u64; N] {
            super::ct_shift_in_bit_mod(acc, bit, modulus)
        }

        /// A context from its four fields, without running a constructor. For the taint
        /// harness: a context whose fields are marked undefined, for the modes that test what
        /// uses a context apart from what builds one.
        pub fn ctx_from_fields<const L: usize>(
            modulus: [u64; L],
            n_prime: u64,
            r_mod_n: [u64; L],
            r2_mod_n: [u64; L],
        ) -> MontgomeryContext<L> {
            MontgomeryContext { modulus, n_prime, r_mod_n, r2_mod_n }
        }

        /// `(modulus, n_prime, r_mod_n, r2_mod_n)`.
        pub fn ctx_fields<const L: usize>(
            ctx: &MontgomeryContext<L>,
        ) -> ([u64; L], u64, [u64; L], [u64; L]) {
            (ctx.modulus, ctx.n_prime, ctx.r_mod_n, ctx.r2_mod_n)
        }
    }
}

/// `crypto/rsa/src/keygen.rs` with a probe onto its private functions.
pub mod keygen {
    include!(concat!(env!("OUT_DIR"), "/keygen.rs"));

    /// The private functions of `keygen`, by their own names.
    pub mod probe {
        use bouncycastle_core::errors::{RNGError, SignatureError};
        use bouncycastle_core::traits::RNG;
        use core::num::NonZeroUsize;

        pub const SMALL_PRIMES: &[u16] = &super::SMALL_PRIMES;

        pub fn mod_u64<const N: usize>(a: &[u64; N], m: u64) -> u64 {
            super::mod_u64(a, m)
        }

        pub fn mul_u64_add<const N: usize>(a: &[u64; N], k: u64, add: u64) -> ([u64; N], u64) {
            super::mul_u64_add(a, k, add)
        }

        pub fn div_u64<const N: usize>(hi: u64, a: &[u64; N], d: u64) -> ([u64; N], u64) {
            super::div_u64(hi, a, d)
        }

        pub fn inv_mod_u64_prime(r: u64, e: u64) -> u64 {
            super::inv_mod_u64_prime(r, e)
        }

        pub fn inverse_of_e_mod<const N: usize>(m: &[u64; N]) -> [u64; N] {
            super::inverse_of_e_mod(m)
        }

        pub fn trailing_zeros<const N: usize>(a: &[u64; N]) -> u32 {
            super::trailing_zeros(a)
        }

        pub fn leading_zeros<const N: usize>(a: &[u64; N]) -> u32 {
            super::leading_zeros(a)
        }

        pub fn mask_to_bits<const N: usize>(a: &mut [u64; N], bits: u32) {
            super::mask_to_bits(a, bits)
        }

        pub fn shr<const N: usize>(a: &[u64; N], shift: u32) -> [u64; N] {
            super::shr(a, shift)
        }

        pub fn shl<const N: usize>(a: &[u64; N], shift: u32) -> [u64; N] {
            super::shl(a, shift)
        }

        pub fn sub_u64<const N: usize>(a: &[u64; N], k: u64) -> [u64; N] {
            super::sub_u64(a, k)
        }

        pub fn gcd<const N: usize>(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
            super::gcd(a, b)
        }

        pub fn div<const N: usize>(a: &[u64; N], d: &[u64; N]) -> [u64; N] {
            super::div(a, d)
        }

        /// `fill_bytes`: every draw the crate makes goes through it (plan K16).
        pub fn fill_bytes(rng: &mut dyn RNG, out: &mut [u8]) -> Result<(), RNGError> {
            super::fill_bytes(rng, out)
        }

        /// The Miller-Rabin test without the stack wipe of the public `is_probable_prime`.
        pub fn is_probable_prime_in_own_frame<const N: usize, const N2: usize, const N21: usize>(
            w: &[u64; N],
            rounds: NonZeroUsize,
            rng: &mut dyn RNG,
        ) -> Result<bool, SignatureError> {
            super::is_probable_prime_in_own_frame::<N, N2, N21>(w, rounds, rng)
        }

        pub fn fill_random<const N: usize>(
            rng: &mut dyn RNG,
            out: &mut [u64; N],
        ) -> Result<(), SignatureError> {
            super::fill_random(rng, out)
        }

        pub fn has_small_factor<const N: usize>(w: &[u64; N]) -> bool {
            super::has_small_factor(w)
        }

        pub fn candidate<const N: usize>(
            rng: &mut dyn RNG,
            out: &mut [u64; N],
        ) -> Result<(), SignatureError> {
            super::candidate(rng, out)
        }

        /// `random_prime` with step 5.5's check against `p` when `p` is given, none otherwise.
        pub fn random_prime<const N: usize, const N2: usize, const N21: usize>(
            rng: &mut dyn RNG,
            rounds: NonZeroUsize,
            max_attempts: usize,
            out: &mut [u64; N],
            p: Option<&[u64; N]>,
        ) -> Result<(), SignatureError> {
            match p {
                Some(p) => super::random_prime::<N, N2, N21>(rng, rounds, max_attempts, out, &|c| {
                    !super::primes_too_close(p, c)
                }),
                None => super::random_prime::<N, N2, N21>(rng, rounds, max_attempts, out, &|_| true),
            }
        }

        pub fn primes_too_close<const N: usize>(p: &[u64; N], q: &[u64; N]) -> bool {
            super::primes_too_close(p, q)
        }
    }
}

/// `crypto/rsa/src/emsa_pkcs1_v1_5.rs` with a probe onto its private functions.
pub mod emsa_pkcs1_v1_5 {
    include!(concat!(env!("OUT_DIR"), "/emsa_pkcs1_v1_5.rs"));

    /// The private functions of `emsa_pkcs1_v1_5`, by their own names.
    pub mod probe {
        use bouncycastle_core::traits::{AlgorithmOID, HashAlgParams};

        pub const MAX_T_LEN: usize = super::MAX_T_LEN;

        /// `T` as a vector: the buffer's first `tLen` bytes.
        pub fn digest_info<H: AlgorithmOID + HashAlgParams>(digest: &[u8]) -> Vec<u8> {
            let mut t = [0u8; super::MAX_T_LEN];
            let t_len = super::digest_info::<H>(digest, &mut t);
            t[..t_len].to_vec()
        }

        pub fn decode_digest_info<H: AlgorithmOID>(t: &[u8], digest: &[u8]) -> bool {
            super::decode_digest_info::<H>(t, digest)
        }
    }
}

/// What `pub(crate)` hides from this crate's binaries and integration tests.
pub mod api {
    use crate::keys::RsaPrivateComponents;
    use crate::size::RsaSize;
    use bouncycastle_core::traits::{HashAlgParams, HashOneShot};
    use bouncycastle_utils::secret::ZeroizablePrimitive;

    pub fn public_exp<const L: usize, const L2: usize, const L21: usize>(
        n: &[u64; L],
        e: u64,
        x: &[u64; L],
    ) -> [u64; L] {
        crate::rsa_core::public_exp::<L, L2, L21>(n, e, x)
    }

    /// `rsa_core::crt_exp_checked` at any widths: the verdict as a `bool`, and `out`.
    #[allow(clippy::too_many_arguments)]
    pub fn crt_exp_checked<
        const L: usize,
        const L2: usize,
        const L21: usize,
        const HALF: usize,
        const HALF2: usize,
        const HALF21: usize,
    >(
        p: &[u64; HALF],
        q: &[u64; HALF],
        d_p: &[u64; HALF],
        d_q: &[u64; HALF],
        q_inv: &[u64; HALF],
        n: &[u64; L],
        e: u64,
        x: &[u64; L],
        out: &mut [u64; L],
    ) -> bool {
        crate::rsa_core::crt_exp_checked::<L, L2, L21, HALF, HALF2, HALF21>(
            p, q, d_p, d_q, q_inv, n, e, x, out,
        )
        .to_bool()
    }

    /// `rsa_core::crt_exp_checked` with its verdict as a word, 1 or 0, selected under the mask
    /// and never branched on: for the taint harness, where the verdict derives from the key.
    #[allow(clippy::too_many_arguments)]
    pub fn crt_exp_checked_word<
        const L: usize,
        const L2: usize,
        const L21: usize,
        const HALF: usize,
        const HALF2: usize,
        const HALF21: usize,
    >(
        p: &[u64; HALF],
        q: &[u64; HALF],
        d_p: &[u64; HALF],
        d_q: &[u64; HALF],
        q_inv: &[u64; HALF],
        n: &[u64; L],
        e: u64,
        x: &[u64; L],
        out: &mut [u64; L],
    ) -> u64 {
        crate::rsa_core::crt_exp_checked::<L, L2, L21, HALF, HALF2, HALF21>(
            p, q, d_p, d_q, q_inv, n, e, x, out,
        )
        .select(1, 0)
    }

    /// The components inside a key-establishment private key.
    pub fn kem_components<K: RsaSize>(
        sk: &crate::rsasve::RsaKEMPrivateKey<K>,
    ) -> &RsaPrivateComponents<K> {
        &sk.0
    }

    /// `rsa_core::wipe_stack_below`.
    pub fn wipe_stack_below<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize>() {
        crate::rsa_core::wipe_stack_below::<T, COUNT, FIXED>()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn crt_exp<
        const L: usize,
        const L2: usize,
        const L21: usize,
        const HALF: usize,
        const HALF2: usize,
        const HALF21: usize,
    >(
        p: &[u64; HALF],
        q: &[u64; HALF],
        d_p: &[u64; HALF],
        d_q: &[u64; HALF],
        q_inv: &[u64; HALF],
        m: &[u64; L],
    ) -> [u64; L] {
        crate::rsa_core::crt_exp::<L, L2, L21, HALF, HALF2, HALF21>(p, q, d_p, d_q, q_inv, m)
    }

    /// `(p, q, dP, dQ, qInv)` of a private key.
    #[allow(clippy::type_complexity)]
    pub fn private_parts<K: RsaSize>(
        sk: &RsaPrivateComponents<K>,
    ) -> (K::HalfLimbs, K::HalfLimbs, K::HalfLimbs, K::HalfLimbs, K::HalfLimbs) {
        (*sk.p(), *sk.q(), *sk.d_p(), *sk.d_q(), *sk.q_inv())
    }

    pub fn in_open_range<K: RsaSize>(x: &K::Limbs, n: &K::Limbs) -> bool {
        crate::rsasve::in_open_range::<K>(x, n)
    }

    pub fn mgf1_xor<M: HashOneShot + HashAlgParams>(seed: &[u8], target: &mut [u8]) {
        crate::mgf1::mgf1_xor::<M>(seed, target)
    }

    pub fn oaep_encode<H, M>(label: &[u8], seed: &[u8], msg: &[u8], em: &mut [u8])
    where
        H: HashOneShot + HashAlgParams,
        M: HashOneShot + HashAlgParams,
    {
        let mut l_hash = [0u8; 64];
        let h_len = crate::eme_oaep::label_hash::<H>(label, &mut l_hash);
        crate::eme_oaep::encode::<H, M>(&l_hash[..h_len], seed, msg, em)
    }

    pub fn oaep_decode_out<H, M>(
        label: &[u8],
        em: &mut [u8],
        exact_len: Option<usize>,
        out: &mut [u8],
    ) -> Option<usize>
    where
        H: HashOneShot + HashAlgParams,
        M: HashOneShot + HashAlgParams,
    {
        let mut l_hash = [0u8; 64];
        let h_len = crate::eme_oaep::label_hash::<H>(label, &mut l_hash);
        crate::eme_oaep::decode_out::<H, M>(&l_hash[..h_len], em, exact_len, out)
    }
}

/// A byte stream as an RNG: the differential runner and the reference model read the same
/// bytes in the same order. An exhausted stream is an RNG failure, which is also how the
/// failure paths are reached. [`stream_rng::ShortRng`] is the RNG `fill_bytes` exists for
/// (plan K16): it reports a count of its own choosing.
pub mod stream_rng {
    use bouncycastle_core::errors::RNGError;
    use bouncycastle_core::key_material::KeyMaterialTrait;
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::RNG;

    pub struct StreamRng {
        data: Vec<u8>,
        pos: usize,
        calls: usize,
        strength: SecurityStrength,
    }

    impl StreamRng {
        pub fn new(data: Vec<u8>, strength: SecurityStrength) -> Self {
            Self { data, pos: 0, calls: 0, strength }
        }

        /// Bytes handed out so far.
        pub fn consumed(&self) -> usize {
            self.pos
        }

        /// Calls of `next_bytes_out` so far, successful or not: "was the RNG touched".
        pub fn calls(&self) -> usize {
            self.calls
        }
    }

    impl RNG for StreamRng {
        fn add_seed_keymaterial(&mut self, _seed: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
            Ok(())
        }

        fn next_int(&mut self) -> Result<u32, RNGError> {
            let mut b = [0u8; 4];
            self.next_bytes_out(&mut b)?;
            Ok(u32::from_be_bytes(b))
        }

        fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
            self.calls += 1;
            out.fill(0);
            if self.pos + out.len() > self.data.len() {
                return Err(RNGError::GenericError("audit stream exhausted"));
            }
            out.copy_from_slice(&self.data[self.pos..self.pos + out.len()]);
            self.pos += out.len();
            Ok(out.len())
        }

        fn fill_keymaterial_out(
            &mut self,
            _out: &mut dyn KeyMaterialTrait,
        ) -> Result<usize, RNGError> {
            Err(RNGError::GenericError("audit stream RNG does not fill key material"))
        }

        fn security_strength(&self) -> SecurityStrength {
            self.strength
        }
    }

    /// An RNG that fills the buffer with `fill` and then reports `claim` bytes written, or
    /// an error of its own when `claim` is `None`: what `RNG::next_bytes_out`'s return value
    /// allows, and what `fill_bytes` must refuse unless the count is the buffer's length.
    pub struct ShortRng {
        pub fill: u8,
        pub claim: Option<usize>,
        pub calls: usize,
    }

    impl RNG for ShortRng {
        fn add_seed_keymaterial(&mut self, _seed: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
            Ok(())
        }

        fn next_int(&mut self) -> Result<u32, RNGError> {
            Err(RNGError::GenericError("audit short RNG has no next_int"))
        }

        fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
            self.calls += 1;
            out.fill(self.fill);
            self.claim.ok_or(RNGError::GenericError("audit short RNG: its own error"))
        }

        fn fill_keymaterial_out(
            &mut self,
            _out: &mut dyn KeyMaterialTrait,
        ) -> Result<usize, RNGError> {
            Err(RNGError::GenericError("audit short RNG does not fill key material"))
        }

        fn security_strength(&self) -> SecurityStrength {
            SecurityStrength::_256bit
        }
    }
}
