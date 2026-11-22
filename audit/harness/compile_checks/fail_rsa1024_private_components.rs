// expect: RsaSigningSize
// Map flag 15: no private key value exists at a verify-only size.
use rsa_audit_harness::RSA1024;
use rsa_audit_harness::keys::RsaPrivateComponents;
fn main() {
    let z = [0u64; 8];
    let _ = RsaPrivateComponents::<RSA1024>::from_crt_components(&z, &z, &z, &z, &z, 65537);
}
