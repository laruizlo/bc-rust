#!/usr/bin/env python3
"""The compile checks that come in families (WP14.3): one program per line of the table
below, written out by check_compile.sh one at a time and built. A program named `fail_*` must
fail to build with the error code and the text given; one named `pass_*` must build, and is
its family's control: it shows the failures are about what they say and not about how the
programs are written.

    python3 -I generated.py list            the names
    python3 -I generated.py show <name>     first line `// expect: <code> | <text>`, then the program

Families
  f04   finding F-04 (357abdb): no encapsulating or key-transporting role toward RSA-1024 or
        RSA-1536 -- RSASVE, RSASVE-HKDF, OAEP as a KEM, OAEP as key transport; the same four at
        RSA-2048 compile, and are called.
  f06   finding F-06 (c08e057, 6bba5cc): a width triple that does not agree is an error when
        the function is instantiated (E0080) -- the probe's four triples for mod_pow, mul_mod,
        mod_pow_public_exponent and is_probable_prime, the one free parameter of
        keygen_from_rng, and the `ec` kernels underneath (montgomery::widening_mul,
        widening_square, redc; barrett::reduce). The agreeing triple compiles.
  m10   WP14.4, row F-06 (b): the public generic functions of M10's inventory that f06 does
        not build -- the `_into` kernels of `ec`, the encodings behind the algorithm traits and
        the signer's `set_salt` (E0080), and the four `*_from_hash` entry points, whose K_LEN
        the type checker fixes (E0271).
  flag13  map flag 13, second half (open): a caller's own `PssParams` with a 100-byte salt
        does not build where the salt is drawn, and builds where it is taken.
  lang  WP14.4, row F-02 (e): the forms in which stable Rust writes a value of a struct type,
        which the listed search `i1` (audit/tools/listed_searches.py) classifies. The forms
        that construct build; the ones the search does not look for do not. No crate code.
  sha1  e061cd6: SHA-1 does not sign, under PKCS #1 v1.5 or PSS, unless it is named as
        `WithoutCollisionResistance<SHA1>`; it verifies either way.
A const assertion fires when the instance is generated, which `cargo check` never does: these
programs are built, not checked.
"""
import sys

CASES = {}


def case(name, expect, body, uses=""):
    CASES[name] = (expect, uses.strip("\n") + "\nfn main() {\n" + body.strip("\n") + "\n}\n")


# ---------------------------------------------------------------- f04
F04_USES = """
use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
use bouncycastle_core::kem_key::EncapsulatingKey;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::key_transport_key::KeyTransportEncryptingKey;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_hkdf::HkdfDescription;
use bouncycastle_sha2::SHA256;
use rsa_audit_harness::rsaes_oaep::OaepParams;
use rsa_audit_harness::rsasve::RsaKEMPublicKey;
use rsa_audit_harness::stream_rng::StreamRng;
use rsa_audit_harness::{RSA1024, RSA1536, RSA2048};
"""
F04_ROLES = {
    "rsasve": "fn role<PK: EncapsulatingKey<(), N, N>, const N: usize>() {}",
    "rsasve_hkdf": "type Params = KdfParams<'static, HkdfDescription<'static, SHA256>, 32>;\n"
                   "    fn role<PK: EncapsulatingKey<Params, N, 32>, const N: usize>() {}",
    "oaep_kem": "type Params = OaepParams<'static, SHA256, SHA256, 32>;\n"
                "    fn role<PK: EncapsulatingKey<Params, N, 32>, const N: usize>() {}",
    "oaep_transport": "type Params = OaepParams<'static, SHA256>;\n"
                      "    fn role<PK: KeyTransportEncryptingKey<Params, N>, const N: usize>() {}",
}
for role, decl in F04_ROLES.items():
    for size, k_len in (("RSA1024", 128), ("RSA1536", 192)):
        case(f"fail_f04_{role}_{size.lower()}", "E0277 | RsaSigningSize",
             f"    {decl}\n    role::<RsaKEMPublicKey<{size}>, {k_len}>();", F04_USES)
    case(f"pass_f04_{role}_rsa2048", "",
         f"    {decl}\n    role::<RsaKEMPublicKey<RSA2048>, 256>();", F04_USES)
# the control that the roles are not only nameable at RSA-2048 but run
case("pass_f04_all_four_called_rsa2048", "", """
    let mut n = [u64::MAX; 32];
    n[0] = u64::MAX - 2;
    let pk = RsaKEMPublicKey::<RSA2048>::new(&n, 65537).unwrap();
    let mut rng = StreamRng::new(vec![7; 1 << 16], SecurityStrength::_256bit);
    let _: Result<(KeyMaterial<256>, [u8; 256]), _> = pk.encaps(&mut rng, ());
    let hkdf = HkdfDescription::<SHA256>::new();
    let _: Result<(KeyMaterial<32>, [u8; 256]), _> =
        pk.encaps(&mut rng, KdfParams::new(&hkdf, b"info", KeyLen::<32>));
    let _: Result<(KeyMaterial<32>, [u8; 256]), _> = pk.encaps(&mut rng, OaepParams::<SHA256>::new(b""));
    let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::MACKey).unwrap();
    let _: Result<[u8; 256], _> = pk.transport(&mut rng, OaepParams::<SHA256>::new(b""), &key);
""", F04_USES)

# ---------------------------------------------------------------- f06
TRIPLES = {"l21_short": (2, 4, 4), "l2_long": (2, 5, 6), "l2_short": (2, 3, 5), "l21_long": (2, 4, 6)}
L2_TEXT, L21_TEXT = "the double width L2 must be 2 * L", "the accumulator width L21 must be 2 * L + 1"
F06_USES = """
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::{barrett, montgomery};
use core::num::NonZeroUsize;
use rsa_audit_harness::keygen::{is_probable_prime, keygen_from_rng};
use rsa_audit_harness::modexp::{MontgomeryContext, mod_pow, mod_pow_public_exponent, mul_mod};
use rsa_audit_harness::stream_rng::StreamRng;
use rsa_audit_harness::RSA2048;
"""
F06_CALLS = {
    "mod_pow": "let ctx = MontgomeryContext::<2>::for_public_modulus(&[7, 0]).unwrap();\n"
               "    let _ = mod_pow::<{L}, {L2}, {L21}>(&[3, 0], &[5, 0], &ctx);",
    "mul_mod": "let ctx = MontgomeryContext::<2>::for_public_modulus(&[7, 0]).unwrap();\n"
               "    let _ = mul_mod::<{L}, {L2}, {L21}>(&[3, 0], &[4, 0], &ctx);",
    "mod_pow_public_exponent": "let ctx = MontgomeryContext::<2>::for_public_modulus(&[7, 0]).unwrap();\n"
                               "    let _ = mod_pow_public_exponent::<{L}, {L2}, {L21}>(&[3, 0], 5, &ctx);",
    "is_probable_prime": "let mut rng = StreamRng::new(vec![7; 1 << 12], SecurityStrength::_256bit);\n"
                         "    let _ = is_probable_prime::<{L}, {L2}, {L21}>(&[0xffffffffffffffc5, 0], NonZeroUsize::new(5).unwrap(), &mut rng);",
}
for fn, call in F06_CALLS.items():
    for tag, (L, L2, L21) in TRIPLES.items():
        text = L2_TEXT if L2 != 2 * L else L21_TEXT
        case(f"fail_f06_{fn}_{tag}", f"E0080 | {text}", "    " + call.format(L=L, L2=L2, L21=L21), F06_USES)
    case(f"pass_f06_{fn}", "", "    " + call.format(L=2, L2=4, L21=5), F06_USES)
# keygen_from_rng: K fixes HALF and HALF2 through its limb types, so HALF21 is the free one
KEYGEN = ("let mut rng = StreamRng::new(Vec::new(), SecurityStrength::_256bit);\n"
          "    let _ = keygen_from_rng::<RSA2048, 16, 32, {H21}>(&mut rng, NonZeroUsize::new(5).unwrap(), SecurityStrength::_112bit);")
case("fail_f06_keygen_from_rng_half21_short", f"E0080 | {L21_TEXT}", "    " + KEYGEN.format(H21=32), F06_USES)
case("fail_f06_keygen_from_rng_half21_long", f"E0080 | {L21_TEXT}", "    " + KEYGEN.format(H21=34), F06_USES)
case("pass_f06_keygen_from_rng", "", "    " + KEYGEN.format(H21=33), F06_USES)
# the `ec` kernels underneath
EC = {
    "widening_mul": ("let _: [u64; {L2}] = montgomery::widening_mul::<2, {L2}>(&[3, 0], &[4, 0]);",
                     {"l2_long": dict(L2=5), "l2_short": dict(L2=3)}, dict(L2=4), "widening_mul's L2 must be exactly 2 * L"),
    "widening_square": ("let _: [u64; {L2}] = montgomery::widening_square::<2, {L2}>(&[3, 0]);",
                        {"l2_long": dict(L2=5), "l2_short": dict(L2=3)}, dict(L2=4), "widening_square's L2 must be exactly 2 * L"),
    "redc": ("let _ = montgomery::redc::<2, {L2}, {L21}>(&[0; {L2}], &[7, 0], 0x6db6db6db6db6db7);",
             {"l21_short": dict(L2=4, L21=4), "l2_long": dict(L2=5, L21=6), "l2_short": dict(L2=3, L21=5),
              "l21_long": dict(L2=4, L21=6)}, dict(L2=4, L21=5), "redc's L"),
    "barrett_reduce": ("let _ = barrett::reduce::<2, {L2}, {L1}>(&[0; {L2}], &[1, 1 << 63], &[0, 0]);",
                       {"l2_long": dict(L2=5, L1=3), "l2_short": dict(L2=3, L1=3), "l1_short": dict(L2=4, L1=2),
                        "l1_long": dict(L2=4, L1=4)}, dict(L2=4, L1=3), "reduce's L"),
}
for fn, (call, bad, good, text) in EC.items():
    for tag, params in bad.items():
        case(f"fail_f06_ec_{fn}_{tag}", f"E0080 | {text}", "    " + call.format(**params), F06_USES)
    case(f"pass_f06_ec_{fn}", "", "    " + call.format(**good), F06_USES)

# ---------------------------------------------------------------- m10
# WP14.4, row F-06 (b): the rest of M10's inventory (audit/tools/listed_searches.py m10). Every
# public generic function whose widths can be written wrong fails to build when they are: the
# two `_into` kernels of `ec`, the encodings behind the algorithm traits (K_LEN is the size's:
# E0080), the signer's `set_salt` (E0080), and the four `*_from_hash` entry points, where
# K_LEN is bound by a type equality on the size's `Modulus` and the error is the type
# checker's (E0271).
M10_USES = """
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::SigningKey;
use bouncycastle_ec::{barrett, montgomery};
use bouncycastle_sha2::SHA256;
use rsa_audit_harness::RSA2048;
use rsa_audit_harness::keys::{RsaPrivateComponents, RsaPrivateKey, RsaPublicComponents, RsaPublicKey};
use rsa_audit_harness::rsassa::{
    RsaDeterministicSignatureAlgorithm, RsaRandomizedSignatureAlgorithm, RsaSignatureAlgorithm,
    sign_from_hash, sign_from_hash_deterministic, sign_from_hash_with_salt, verify_from_hash,
};
use rsa_audit_harness::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use rsa_audit_harness::rsassa_pss::{NoSalt, RSASSA_PSS};
use rsa_audit_harness::stream_rng::StreamRng;
type V15 = RSASSA_PKCS1_v1_5<RSA2048, SHA256>;
type Pss = RSASSA_PSS<RSA2048, SHA256>;
type PssNoSalt = RSASSA_PSS<RSA2048, SHA256, NoSalt<SHA256>>;
"""
INTO = {
    "widening_mul_into": ("let mut out = [0u64; {L2}];\n    montgomery::widening_mul_into::<2, {L2}>(&[3, 0], &[4, 0], &mut out);",
                          {"l2_long": dict(L2=5), "l2_short": dict(L2=3)}, dict(L2=4), "widening_mul's L2 must be exactly 2 * L"),
    "barrett_reduce_into": ("let mut out = [0u64; 2];\n    barrett::reduce_into::<2, {L2}, {L1}>(&[0; {L2}], &[1, 1 << 63], &[0, 0], &mut out);",
                            {"l2_long": dict(L2=5, L1=3), "l1_short": dict(L2=4, L1=2)}, dict(L2=4, L1=3), "reduce's L"),
}
for fn, (call, bad, good, text) in INTO.items():
    for tag, params in bad.items():
        case(f"fail_m10_ec_{fn}_{tag}", f"E0080 | {text}", "    " + call.format(**params), M10_USES)
    case(f"pass_m10_ec_{fn}", "", "    " + call.format(**good), M10_USES)
K_LEN_TEXT = "K_LEN is the size's modulus length"
EMSA = {
    "v15_emsa_verify": "let _ = V15::emsa_verify::<{K}>(&[0u8; 32], &[0u8; {K}]);",
    "v15_emsa_encode": "let _ = V15::emsa_encode::<{K}>(&[0u8; 32]);",
    "pss_emsa_verify": "let _ = Pss::emsa_verify::<{K}>(&[0u8; 32], &[0u8; {K}]);",
    "pss_emsa_encode": "let _ = Pss::emsa_encode::<{K}>(&[0u8; 32], &[0u8; 32]);",
    "pss_unsalted_emsa_encode": "let _ = PssNoSalt::emsa_encode::<{K}>(&[0u8; 32]);",
}
for name, call in EMSA.items():
    case(f"fail_m10_{name}_k_len_128", f"E0080 | {K_LEN_TEXT}", "    " + call.format(K=128), M10_USES)
case("pass_m10_emsa_at_the_size", "", "\n".join("    " + c.format(K=256) for c in EMSA.values()), M10_USES)
KEYS = ("let z = [0u64; 16];\n"
        "    let sk = RsaPrivateComponents::<RSA2048>::from_crt_components(&z, &z, &z, &z, &z, 65537).unwrap();\n"
        "    let pk = RsaPublicComponents::<RSA2048>::new(&[1u64; 32], 65537).unwrap();\n"
        "    let mut rng = StreamRng::new(vec![7; 64], SecurityStrength::_256bit);\n"
        "    let _ = (&sk, &pk, &mut rng);\n")
FROM_HASH = {
    "sign_from_hash_with_salt": "let _ = sign_from_hash_with_salt::<Pss, {K}>(&sk.key(), &[0u8; 32], &[0u8; 32]);",
    "sign_from_hash": "let _ = sign_from_hash::<Pss, {K}>(&sk.key(), &[0u8; 32], &mut rng);",
    "sign_from_hash_deterministic": "let _ = sign_from_hash_deterministic::<V15, {K}>(&sk.key(), &[0u8; 32]);",
    "verify_from_hash": "let _ = verify_from_hash::<V15, {K}>(&pk.key(), &[0u8; 32], &[0u8; {K}]);",
}
for name, call in FROM_HASH.items():
    case(f"fail_m10_{name}_k_len_128", "E0271 | Modulus", "    " + KEYS + "    " + call.format(K=128), M10_USES)
case("pass_m10_from_hash_at_the_size", "", "    " + KEYS + "\n".join("    " + c.format(K=256) for c in FROM_HASH.values()), M10_USES)
SET_SALT = (KEYS + "    let key: RsaPrivateKey<Pss> = sk.key();\n"
            "    let mut signer = SigningKey::<Pss, 256>::create_signer(&key, &mut rng, None).unwrap();\n"
            "    signer.set_salt([0u8; {N}]);")
# keygen_from_rng: f06 has its one free parameter, HALF21. HALF and HALF2 are the size's limb
# counts by a type equality, so the probe's other two triples are the type checker's.
M10_KEYGEN = ("let mut rng = StreamRng::new(Vec::new(), SecurityStrength::_256bit);\n"
              "    let _ = rsa_audit_harness::keygen::keygen_from_rng::<RSA2048, {H}, {H2}, {H21}>(\n"
              "        &mut rng, core::num::NonZeroUsize::new(5).unwrap(), SecurityStrength::_112bit);")
case("fail_m10_keygen_from_rng_half2_long", "E0271 | Limbs", "    " + M10_KEYGEN.format(H=16, H2=33, H21=33), M10_USES)
case("fail_m10_keygen_from_rng_half2_short", "E0271 | Limbs", "    " + M10_KEYGEN.format(H=16, H2=31, H21=33), M10_USES)
case("fail_m10_keygen_from_rng_half_short", "E0271 | HalfLimbs", "    " + M10_KEYGEN.format(H=15, H2=32, H21=33), M10_USES)
case("fail_m10_set_salt_31", "E0080 | the salt is the algorithm's salt length", "    " + SET_SALT.format(N=31), M10_USES)
case("pass_m10_set_salt_32", "", "    " + SET_SALT.format(N=32), M10_USES)

# ---------------------------------------------------------------- flag13
# Map flag 13, second half (open; plan E7): a caller's own `PssParams` with a salt past the
# documented 64 bytes. The two entry points that draw the salt refuse to build; the three that
# take it do build, and the probe `a_foreign_pss_parameter_set_past_its_documented_salt_bound
# _panics` shows what they then do.
FLAG13_USES = M10_USES + """
use bouncycastle_utils::const_str::ConstStr;
use rsa_audit_harness::rsassa_pss::{PssParams, SaltedPss};
struct OwnSalt<const S: usize>;
impl<const S: usize> PssParams<SHA256> for OwnSalt<S> {
    const SALT_LEN: usize = S;
    const NAME_SUFFIX: ConstStr<32> = ConstStr::concat(&["-own"]);
    fn mask(_seed: &[u8], mask: &mut [u8]) {
        mask.fill(0);
    }
}
impl<const S: usize> SaltedPss for OwnSalt<S> {}
type Own<const S: usize> = RSASSA_PSS<RSA2048, SHA256, OwnSalt<S>>;
"""
DRAWS = {
    "sign_from_hash": ("let _ = sign_from_hash::<Own<{S}>, 256>(&sk.key(), &[0u8; 32], &mut rng);", "the salt fits the buffer"),
    "create_signer": ("let key: RsaPrivateKey<Own<{S}>> = sk.key();\n"
                      "    let _ = SigningKey::<Own<{S}>, 256>::create_signer(&key, &mut rng, None);", "the salt fits the signer's buffer"),
}
for name, (call, text) in DRAWS.items():
    case(f"fail_flag13_{name}_salt_100", f"E0080 | {text}", "    " + KEYS + "    " + call.format(S=100), FLAG13_USES)
case("pass_flag13_drawing_entry_points_salt_64", "",
     "    " + KEYS + "\n".join("    " + c.format(S=64) for c, _ in DRAWS.values()), FLAG13_USES)
case("pass_flag13_taking_entry_points_salt_100", "", "    " + KEYS + """    let _ = sign_from_hash_with_salt::<Own<100>, 256>(&sk.key(), &[0u8; 32], &[0u8; 100]);
    let _ = Own::<100>::emsa_encode::<256>(&[0u8; 32], &[0u8; 100]);
    let _ = Own::<100>::emsa_verify::<256>(&[0u8; 32], &[0u8; 256]);""", FLAG13_USES)

# ---------------------------------------------------------------- lang
# The premise of the listed search `i1`: a key value can be written only in the forms the
# search classifies. These programs use no crate code; they ask the compiler which forms exist.
LANG_ITEMS = """
#![allow(dead_code, unused_variables)]
mod keys {
    pub struct Named { x: u8 }                  // private field, as the four types of keys.rs
    pub struct Tuple(pub(crate) u8);            // crate-visible field, as the two KEM key types
    pub struct Closed(u8);                      // a tuple struct with a private field
    impl Named {
        pub fn a(x: u8) -> Self { Self { x } }
        pub fn b(x: u8) -> Self { Named::<> { x } }
    }
    impl Tuple {
        pub fn a(x: u8) -> Self { Self(x) }
        pub fn b(x: u8) -> Self { Self { 0: x } }
        pub fn c(x: Option<u8>) -> Option<Self> { x.map(Self) }
    }
}
use keys::{Closed, Named, Tuple};
type Alias = Tuple;
trait Tr { type A; type B; type C; fn a() -> Self::A; fn b() -> Self::B; }
struct Unit;
impl Tr for Unit {
    type A = keys::Open; type B = Tuple; type C = Closed;
    fn a() -> Self::A { Self::A { x: 1 } }      // through an associated type of the enclosing impl
    fn b() -> Self::B { Self::B { 0: 1 } }
}
fn bound<X: Tr<B = Tuple>>() -> Tuple { X::B { 0: 1 } }   // and of a parameter, under an equality bound
"""
LANG_ITEMS = LANG_ITEMS.replace("pub struct Closed(u8);", "pub struct Closed(u8);\n    pub struct Open { pub x: u8 }")
case("pass_lang_forms_that_construct", "", """    let t1 = Tuple(1);                           // the constructor, called
    let t2 = Tuple { 0: 1 };                     // braces on a tuple struct
    let t3 = Alias { 0: 1 };                     // braces through an alias
    let t4: Option<Tuple> = Some(1u8).map(Tuple);  // the constructor as a function
    let f: fn(u8) -> Tuple = Tuple;
    let t5 = Tuple::<>(1);                       // with generic arguments
    let (n, t6, t7) = (Named::a(1), Tuple::b(1), Tuple::c(Some(1)));
    let (a, b, c) = (<Unit as Tr>::a(), <Unit as Tr>::b(), bound::<Unit>());""", LANG_ITEMS)
for name, expect, line in (
    ("alias_as_function", "E0423 | type alias", "let x = Alias(1);"),
    ("associated_type_as_function", "E0575 | found associated type", "let x = <Unit as Tr>::B(1);"),
    ("qualified_path_with_braces", "E0658 | qualified paths", "let x = <Unit as Tr>::B { 0: 1 };"),
    ("associated_type_of_a_concrete_type", "E0223 | ambiguous associated type", "let x = Unit::B { 0: 1 };"),
    ("private_field_with_braces", "E0451 | private", "let x = Named { x: 1 };"),
    ("private_field_of_a_tuple_struct", "E0423 | private fields", "let x = Closed(1);"),
    ("private_field_through_an_alias", "E0451 | private", "type Other = Closed;\n    let x = Other { 0: 1 };"),
):
    case(f"fail_lang_{name}", expect, "    " + line, LANG_ITEMS)
case("fail_lang_associated_type_of_a_parameter_without_a_bound", "E0071 | expected struct", "",
     LANG_ITEMS + "fn unbound<X: Tr>() {\n    let x = X::B { 0: 1 };\n}\n")

# ---------------------------------------------------------------- sha1
SHA1_USES = """
use bouncycastle_core::hazmat::WithoutCollisionResistance;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, OneShotSigningKey, OneShotVerifyingKey, SignatureAlgorithm,
};
use bouncycastle_digest::sha1::SHA1;
use bouncycastle_sha2::SHA256;
use rsa_audit_harness::RSA2048;
use rsa_audit_harness::keys::{RsaPrivateKey, RsaPublicKey};
use rsa_audit_harness::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use rsa_audit_harness::rsassa_pss::RSASSA_PSS;
"""
V15_SIGN = "fn signs<SK: DeterministicOneShotSigningKey<A, 256>, A: SignatureAlgorithm>() {}\n    signs::<RsaPrivateKey<RSASSA_PKCS1_v1_5<RSA2048, {H}>>, RSASSA_PKCS1_v1_5<RSA2048, {H}>>();"
PSS_SIGN = "fn signs<SK: OneShotSigningKey<A, 256>, A: SignatureAlgorithm>() {}\n    signs::<RsaPrivateKey<RSASSA_PSS<RSA2048, {H}>>, RSASSA_PSS<RSA2048, {H}>>();"
V15_VERIFY = "fn verifies<PK: OneShotVerifyingKey<A, 256>, A: SignatureAlgorithm>() {}\n    verifies::<RsaPublicKey<RSASSA_PKCS1_v1_5<RSA2048, {H}>>, RSASSA_PKCS1_v1_5<RSA2048, {H}>>();"
case("fail_sha1_v15_signs", "E0277 | CollisionResistantHash", "    " + V15_SIGN.replace("{H}", "SHA1"), SHA1_USES)
case("fail_sha1_pss_signs", "E0277 | CollisionResistantHash", "    " + PSS_SIGN.replace("{H}", "SHA1"), SHA1_USES)
case("pass_sha1_v15_signs_with_sha256", "", "    " + V15_SIGN.replace("{H}", "SHA256"), SHA1_USES)
case("pass_sha1_pss_signs_with_sha256", "", "    " + PSS_SIGN.replace("{H}", "SHA256"), SHA1_USES)
case("pass_sha1_v15_verifies", "", "    " + V15_VERIFY.replace("{H}", "SHA1"), SHA1_USES)
case("pass_sha1_v15_signs_when_named_without_collision_resistance", "",
     "    " + V15_SIGN.replace("{H}", "WithoutCollisionResistance<SHA1>"), SHA1_USES)

if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(CASES))
    elif sys.argv[1:2] == ["show"] and sys.argv[2] in CASES:
        expect, source = CASES[sys.argv[2]]
        print(f"// expect: {expect}\n// generated by compile_checks/generated.py: {sys.argv[2]}\n#![allow(unused_imports)]\n{source}", end="")
    else:
        sys.exit(__doc__)
