#!/usr/bin/env python3
"""Cross-check of rsa_ref.py against OpenSSL, through the PyPI package `cryptography`.

    pip install --target DEPS cryptography
    python3 -I audit/ref/selftest_openssl.py --deps DEPS

An independent implementation, not a specification: agreement here supports the model, and a
disagreement has to be settled from the RFC text. OpenSSL generates the keys.
"""
import argparse
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rsa_ref as M  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--deps", required=True)
    a = ap.parse_args()
    sys.path.insert(0, a.deps)
    from cryptography.hazmat.backends.openssl import backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    import cryptography

    H = {"SHA-1": hashes.SHA1, "SHA-224": hashes.SHA224, "SHA-256": hashes.SHA256,
         "SHA-384": hashes.SHA384, "SHA-512": hashes.SHA512, "SHA-512/224": hashes.SHA512_224,
         "SHA-512/256": hashes.SHA512_256, "SHA3-256": hashes.SHA3_256, "SHA3-512": hashes.SHA3_512}
    rnd = random.Random(31337)
    checked = failed = 0
    notes = []
    for bits in (2048, 3072):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        nums = key.private_numbers()
        k_len = bits // 8
        sk = M.PrivateComponents(nums.p, nums.q, nums.dmp1, nums.dmq1, nums.iqmp, k_len)
        pk = M.PublicComponents(nums.public_numbers.n, 65537, k_len)
        assert sk.n == pk.n and sk.h_key(65537)
        pub = key.public_key()
        for hn, hc in H.items():
            h = M.HASHES[hn]
            msg = rnd.randbytes(rnd.randrange(0, 300))
            # PKCS #1 v1.5: deterministic, so the signatures must be equal byte for byte
            try:
                theirs = key.sign(msg, padding.PKCS1v15(), hc())
                ok = theirs == M.rsassa_pkcs1_v1_5_sign(sk, h, msg) and M.rsassa_pkcs1_v1_5_verify(pk, h, msg, theirs)
                checked += 1
                failed += not ok
            except Exception as err:          # a hash this OpenSSL build does not pair with v1.5
                notes.append(f"v1.5/{hn}: {type(err).__name__}")
            # PSS, both directions, several salt lengths and MGF1 hashes
            for mn in ("SHA-1", "SHA-256", "SHA-512", hn):
                mgf_m, mgf_o = M.Mgf("mgf1", M.HASHES[mn]), padding.MGF1(H[mn]())
                for s_len in (0, 1, 20, h.out_len, k_len - h.out_len - 2):
                    pad = padding.PSS(mgf=mgf_o, salt_length=s_len)
                    try:
                        theirs = key.sign(msg, pad, hc())
                        ok = M.rsassa_pss_verify(pk, h, mgf_m, msg, theirs, s_len)
                        ours = M.rsassa_pss_sign(sk, h, mgf_m, msg, rnd.randbytes(s_len))
                        pub.verify(ours, msg, pad, hc())
                        if s_len > 0:           # a wrong salt length must be refused by both
                            ok &= not M.rsassa_pss_verify(pk, h, mgf_m, msg, theirs, s_len - 1)
                            try:
                                pub.verify(ours, msg, padding.PSS(mgf=mgf_o, salt_length=s_len - 1), hc())
                                ok = False
                            except InvalidSignature:
                                pass
                    except InvalidSignature:
                        ok = False
                    checked += 1
                    failed += not ok
        # OAEP, both directions, labels, label hash and MGF1 hash chosen separately
        for hn in ("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256"):
            h = M.HASHES[hn]
            for mn in ("SHA-1", "SHA-256", "SHA-512"):
                label = rnd.randbytes(rnd.randrange(0, 30))
                pad = padding.OAEP(mgf=padding.MGF1(H[mn]()), algorithm=H[hn](), label=label or None)
                for m_len in (0, 1, 32, k_len - 2 * h.out_len - 2):
                    msg = rnd.randbytes(m_len)
                    mgf_m = M.Mgf("mgf1", M.HASHES[mn])
                    ours = M.rsaes_oaep_encrypt(pk, h, mgf_m, label, msg, rnd.randbytes(h.out_len))
                    try:
                        ok = key.decrypt(ours, pad) == msg
                        ok &= M.rsaes_oaep_decrypt(sk, h, mgf_m, label, pub.encrypt(msg, pad)) == msg
                    except UnsupportedAlgorithm:
                        notes.append(f"OAEP/{hn}/MGF1-{mn}: not supported by this OpenSSL binding")
                        continue
                    checked += 1
                    failed += not ok
    for hn, hc in (("sha1", hashes.SHA1), ("sha256", hashes.SHA256), ("sha512", hashes.SHA512)):
        for _ in range(20):
            ikm, salt, info = rnd.randbytes(rnd.randrange(1, 600)), rnd.randbytes(rnd.randrange(0, 80)), rnd.randbytes(rnd.randrange(0, 80))
            length = rnd.randrange(1, 255 * hc().digest_size + 1)
            theirs = HKDF(algorithm=hc(), length=length, salt=salt or None, info=info).derive(ikm)
            checked += 1
            failed += theirs != M.hkdf(hn, salt, ikm, info, length)
    print(f"cryptography {cryptography.__version__}, {backend.openssl_version_text()}")
    if notes:
        print("notes:", sorted(set(notes)))
    print(f"OpenSSL cross-check: {checked} checked, {failed} failed")
    print("CROSS-CHECK PASSED" if failed == 0 else "CROSS-CHECK FAILED")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
