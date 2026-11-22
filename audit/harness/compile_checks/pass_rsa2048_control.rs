// The same three constructions at a signing size compile: the failures above are about the
// size, not about how the probes are written.
use bouncycastle_core::kem_key::DecapsulatingKey;
use bouncycastle_core::signature_key::DeterministicOneShotSigningKey;
use bouncycastle_sha2::SHA256;
use rsa_audit_harness::RSA2048;
use rsa_audit_harness::keys::{RsaPrivateComponents, RsaPrivateKey};
use rsa_audit_harness::rsasve::RsaKEMPrivateKey;
use rsa_audit_harness::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use rsa_audit_harness::size::RsaSigningSize;
use rsa_audit_harness::stream_rng::StreamRng;
fn sign(sk: &RsaPrivateKey<RSASSA_PKCS1_v1_5<RSA2048, SHA256>>) {
    let _ = sk.sign_deterministic(b"", None);
}
fn decaps(sk: &RsaKEMPrivateKey<RSA2048>, ct: &[u8; 256]) {
    let _ = sk.decaps(ct, ());
}
fn main() {
    let z = [0u64; 16];
    let _ = RsaPrivateComponents::<RSA2048>::from_crt_components(&z, &z, &z, &z, &z, 65537);
    let mut rng = StreamRng::new(Vec::new(), bouncycastle_core::security_strength::SecurityStrength::_256bit);
    let _ = <RSA2048 as RsaSigningSize>::keygen(&mut rng);
    let _ = (sign, decaps);
}
