// expect: RsaSigningSize
// Map flag 15: no key generation at a verify-only size.
use rsa_audit_harness::RSA1536;
use rsa_audit_harness::size::RsaSigningSize;
use rsa_audit_harness::stream_rng::StreamRng;
fn main() {
    let mut rng = StreamRng::new(Vec::new(), bouncycastle_core::security_strength::SecurityStrength::_256bit);
    let _ = <RSA1536 as RsaSigningSize>::keygen(&mut rng);
}
