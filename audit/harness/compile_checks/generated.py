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
