// expect: RsaSigningSize
// Map flag 15: the signing role is not implemented for a key at a verify-only size.
use bouncycastle_core::signature_key::DeterministicOneShotSigningKey;
use bouncycastle_sha2::SHA256;
use rsa_audit_harness::RSA1024;
use rsa_audit_harness::keys::RsaPrivateKey;
use rsa_audit_harness::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
fn sign(sk: &RsaPrivateKey<RSASSA_PKCS1_v1_5<RSA1024, SHA256>>) {
    let _ = sk.sign_deterministic(b"", None);
}
fn main() {
    let _ = sign;
}
