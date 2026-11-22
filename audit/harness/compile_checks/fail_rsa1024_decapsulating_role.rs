// expect: no method named `decaps`
// The decapsulating role needs a signing size: the impl is bounded by `K: RsaSigningSize`, so at
// RSA1024 the method does not exist. (Since 357abdb the encapsulating role is bounded the same
// way: generated.py's F-04 family.) The control file shows the same call compiling at RSA2048.
use bouncycastle_core::kem_key::DecapsulatingKey;
use rsa_audit_harness::RSA1024;
use rsa_audit_harness::rsasve::RsaKEMPrivateKey;
fn decaps(sk: &RsaKEMPrivateKey<RSA1024>, ct: &[u8; 128]) {
    let _ = sk.decaps(ct, ());
}
fn main() {
    let _ = decaps;
}
