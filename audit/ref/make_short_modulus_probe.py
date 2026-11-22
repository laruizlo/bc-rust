#!/usr/bin/env python3
"""Generates harness/tests/data/short_modulus.rs: the constants of the probe that shows what
obligation E6 says happens when a signature key type holds a modulus shorter than its width
(plan G3, map flag 4).

    python3 -I audit/ref/make_short_modulus_probe.py --deps DEPS > audit/harness/tests/data/short_modulus.rs

The key is two 1022-bit primes: n has 2043 or 2044 bits inside an RSA-2048 key type, and is
still 256 octets long, so signatures have the length the type expects. RFC 8017 section 8.1.1
sets emBits = modBits - 1; the crate fixes emBits = 8*K_LEN - 1 = 2047 (emsa_pss.rs:71, 100).
The model computes, in both readings:
  SIGNABLE   which of 64 fixed salts the crate's signer can sign at all (its EM is below n);
  SIG_CRATE  a signature the crate's way whose EM is at or above 2^(modBits-1), so a conforming
             verifier refuses it at section 9.1.2 step 6;
  SIG_RFC    a signature the RFC's way that the crate's reading refuses.
OpenSSL (through `cryptography`, from DEPS) is asked to verify both and must side with the RFC
reading, or nothing is written. Deterministic: fixed seed.
"""
import argparse
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rsa_ref as M  # noqa: E402


def is_prime(n, rnd):
    for p in M.SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(40):
        x = pow(rnd.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deps", required=True)
    a = ap.parse_args()
    sys.path.insert(0, a.deps)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

    rnd = random.Random(20261120)
    e = 65537
    primes = []
    while len(primes) < 2:
        c = rnd.getrandbits(1022) | (1 << 1021) | 1
        if (c - 1) % e and is_prime(c, rnd) and c not in primes:
            primes.append(c)
    p, q = primes
    sk = M.PrivateComponents(p, q, pow(e, -1, p - 1), pow(e, -1, q - 1), pow(q, -1, p), 256)
    pk = M.PublicComponents(sk.n, e, 256)
    mod_bits = sk.n.bit_length()
    assert sk.h_key(e) and mod_bits in (2043, 2044)
    h = M.HASHES["SHA-256"]
    mgf = M.Mgf("mgf1", h)
    m_hash = bytes([0x5A]) * 32
    crate_bits, rfc_bits = 8 * 256 - 1, mod_bits - 1

    def salt(i):
        return i.to_bytes(4, "big") * 8

    def model_verify(sig, em_bits):
        try:
            em = M.i2osp(M.rsavp1(pk, M.os2ip(sig)), -(-em_bits // 8))
        except M.ModelError:
            return False
        return M.emsa_pss_verify_from_hash(h, mgf, m_hash, em, em_bits, 32)

    signable = [i for i in range(64)
                if M.os2ip(M.emsa_pss_encode_from_hash(h, mgf, m_hash, salt(i), crate_bits)) < sk.n]
    # Of those, the ones a conforming verifier refuses: the encoding has more than modBits - 1 bits.
    nonconforming = [i for i in signable if M.os2ip(
        M.emsa_pss_encode_from_hash(h, mgf, m_hash, salt(i), crate_bits)) >> rfc_bits]
    for i in signable:
        s = M.i2osp(sk.crt_exp(M.os2ip(M.emsa_pss_encode_from_hash(h, mgf, m_hash, salt(i), crate_bits))), 256)
        assert model_verify(s, crate_bits) and model_verify(s, rfc_bits) == (i not in nonconforming)
    # The crate's way, with EM in [2^(modBits-1), n): signable, and outside the RFC's range.
    for j in range(100000):
        em = M.os2ip(M.emsa_pss_encode_from_hash(h, mgf, m_hash, salt(j), crate_bits))
        if (1 << rfc_bits) <= em < sk.n:
            break
    sig_crate = M.i2osp(sk.crt_exp(em), 256)
    # The RFC's way, with a salt for which the crate's reading refuses the result.
    for k in range(100000):
        em = M.os2ip(M.emsa_pss_encode_from_hash(h, mgf, m_hash, salt(k), rfc_bits))
        sig_rfc = M.i2osp(sk.crt_exp(em), 256)
        if not model_verify(sig_rfc, crate_bits):
            break
    assert model_verify(sig_rfc, rfc_bits) and not model_verify(sig_rfc, crate_bits)
    assert model_verify(sig_crate, crate_bits) and not model_verify(sig_crate, rfc_bits)
    # How often the crate's reading refuses a conforming signature, over 256 salts.
    refused = sum(not model_verify(M.i2osp(sk.crt_exp(M.os2ip(
        M.emsa_pss_encode_from_hash(h, mgf, m_hash, salt(1000 + i), rfc_bits))), 256), crate_bits) for i in range(256))

    # OpenSSL's verdicts.
    d = pow(e, -1, (p - 1) * (q - 1))
    key = rsa.RSAPrivateNumbers(p, q, d, sk.d_p, sk.d_q, sk.q_inv, rsa.RSAPublicNumbers(e, sk.n)).private_key()
    pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

    def openssl_verify(sig):
        try:
            key.public_key().verify(sig, m_hash, pad, utils.Prehashed(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
    assert openssl_verify(sig_rfc), "OpenSSL must accept the RFC-style signature"
    assert not openssl_verify(sig_crate), "OpenSSL must reject the crate-style signature"

    def limbs(x, n):
        return "[" + ", ".join(f"0x{(x >> (64 * i)) & (2 ** 64 - 1):016x}" for i in range(n)) + "]"

    def bytes_(b):
        return "[" + ", ".join(f"0x{v:02x}" for v in b) + "]"
    out = [
        "// Generated by audit/ref/make_short_modulus_probe.py (seed 20261120). Do not edit.",
        f"// n has {mod_bits} bits; the key type is RSA-2048. Checked at generation: the model in the",
        "// RFC 8017 reading and OpenSSL accept SIG_RFC and reject SIG_CRATE; the model in the",
        "// crate's reading does the opposite.",
        f"pub const MODULUS_BITS: usize = {mod_bits};",
        f"pub const P: [u64; 16] = {limbs(p, 16)};",
        f"pub const Q: [u64; 16] = {limbs(q, 16)};",
        f"pub const D_P: [u64; 16] = {limbs(sk.d_p, 16)};",
        f"pub const D_Q: [u64; 16] = {limbs(sk.d_q, 16)};",
        f"pub const Q_INV: [u64; 16] = {limbs(sk.q_inv, 16)};",
        "pub const M_HASH: [u8; 32] = [0x5a; 32];",
        "/// Salt i is the four big-endian bytes of i, eight times.",
        "/// Of salts 0..64: those whose encoding (emBits = 2047) is below n, by the model.",
        f"pub const SIGNABLE: &[u32] = &{signable};",
        "/// A signable salt whose encoding is at or above 2^(modBits-1).",
        f"pub const SALT_CRATE: u32 = {j};",
        f"pub const SIG_CRATE: [u8; 256] = {bytes_(sig_crate)};",
        f"pub const SALT_RFC: u32 = {k};",
        f"pub const SIG_RFC: [u8; 256] = {bytes_(sig_rfc)};",
    ]
    print("\n".join(out))
    print(f"n bits {mod_bits}; signable salts {len(signable)}/64 {signable}, of which a conforming verifier "
          f"refuses {len(nonconforming)} {nonconforming}; crate salt {j}; rfc salt {k}; "
          f"the crate's reading refuses {refused}/256 conforming signatures", file=sys.stderr)


if __name__ == "__main__":
    main()
