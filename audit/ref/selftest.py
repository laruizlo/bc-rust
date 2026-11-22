#!/usr/bin/env python3
"""Known answers for rsa_ref.py. The model judges nothing until this passes.

    python3 -I audit/ref/selftest.py --rfc DIR --wycheproof DIR --acvp DIR [--require-all]

Sources of the known answers (none is produced by the code under audit):
  RFC text files   rfc8017.txt (DigestInfo prefixes, lHash of the empty label), rfc5869.txt
                   (appendix A test cases), read and parsed here, not transcribed.
  Wycheproof       C2SP/wycheproof testvectors_v1: PKCS #1 v1.5 verify and sign, PSS verify,
                   OAEP decrypt. Every RSA file whose scheme the model implements.
  ACVP samples     usnistgov/ACVP-Server gen-val/json-files: RSA sigGen, sigVer (186-5, 186-2),
                   signaturePrimitive 2.0, decryptionPrimitive 56Br2, keyGen, KAS-IFC-SSC, KTS-IFC.
A missing source is reported as SKIPPED; with --require-all it is a failure.
Standard library only. Run with -I: the vector directories are untrusted input.
"""
import argparse
import json
import math
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rsa_ref as M  # noqa: E402

RESULTS = []          # (section, checked, failed, note)


def record(section, checked, failed, note=""):
    RESULTS.append((section, checked, failed, note))
    status = "ok  " if failed == 0 and checked > 0 else ("SKIP" if checked == 0 and failed == 0 else "FAIL")
    print(f"[{status}] {section}: {checked} checked, {failed} failed {('- ' + note) if note else ''}")


def hx(s):
    return bytes.fromhex(s)


def hi(s):
    return int(s, 16) if s else 0


# ------------------------------------------------------------------ kernel, by arithmetic
def kernel():
    rnd = random.Random(20261119)
    checked = failed = 0
    for L in (1, 2, 3, 4, 8, 16):
        Rr = M.R(L)
        mods = [3, Rr - 1, (Rr >> 1) + 1] + [rnd.randrange(3, Rr) | 1 for _ in range(40)]
        for n in mods:
            ctx = M.MontgomeryContext.for_public_modulus(n, L)
            np_ = ctx.n_prime
            ok = (n * np_) % M.BETA == M.BETA - 1                                  # M1
            Rinv = pow(Rr, -1, n)
            for T in (0, n * Rr - 1, (n - 1) ** 2, (Rr - 1) * (n - 1), rnd.randrange(n * Rr)):
                high, extra = M.redc(T, n, np_, L)                                  # S6
                u = high + extra * Rr
                ok &= extra in (0, 1) and u < 2 * n and (u * Rr - T) % n == 0
                ok &= M.redc_normalize(T, n, np_, L) == (T * Rinv) % n              # M3
            a, b = rnd.randrange(Rr), rnd.randrange(n)
            ok &= M.to_montgomery(a, ctx) == (a * Rr) % n                           # M4
            ok &= M.from_montgomery(M.to_montgomery(a, ctx), ctx) == a % n
            x, y = rnd.randrange(n), rnd.randrange(n)
            xb, yb = M.to_montgomery(x, ctx), M.to_montgomery(y, ctx)
            ok &= M.from_montgomery(M.mont_mul(xb, yb, n, np_, L), ctx) == (x * y) % n
            ok &= M.from_montgomery(M.mont_square(xb, n, np_, L), ctx) == (x * x) % n
            ok &= M.mul_mod(a, b, ctx) == (a * b) % n                               # M5
            e = rnd.randrange(Rr)
            ok &= M.mod_pow(a, e, ctx) == pow(a, e, n) and M.mod_pow(0, 0, ctx) == 1  # M9
            ok &= M.pow2_mod(64 * L, n, L) == ctx.r_mod_n and M.pow2_mod(128 * L, n, L) == ctx.r2_mod_n
            checked += 1
            failed += not ok
        # S1, S2 identities; M6-M8 for odd and even moduli
        for _ in range(200):
            a, b = rnd.randrange(Rr), rnd.randrange(Rr)
            s, c = M.nat_add(a, b, L)
            d, br = M.nat_sub(a, b, L)
            m = rnd.randrange(1, Rr)
            acc = rnd.randrange(m)
            ok = s + c * Rr == a + b and d - br * Rr == a - b and (br == 1) == (a < b)
            ok &= M.ct_shift_in_bit_mod(acc, 1, m, L) == (2 * acc + 1) % m
            ok &= M.reduce_wide(a * b, m, 2 * L, L) == (a * b) % m
            ok &= M.sub_mod(a % m, b % m, m, L) == (a - b) % m
            checked += 1
            failed += not ok
    # M2': the decisions are the digits of floor(2^k/p), and they give p back
    for h in (64, 128, 256):
        for _ in range(10):
            p = rnd.getrandbits(h) | (1 << (h - 1)) | 1
            dec = M.pow2_mod_decisions(2 * h, p)
            Q = int("".join(map(str, dec)), 2)
            ok = Q == (1 << (2 * h)) // p and sum(dec[:h - 1]) == 0 and dec[h - 1] == 1
            # p = floor(2^2h / Q) whenever p is not a power of two (true for odd p > 1)
            ok &= (1 << (2 * h)) // Q == p
            checked += 1
            failed += not ok
    # limb conversion round trip
    for L in (1, 4, 32):
        x = rnd.randrange(M.R(L))
        ok = M.from_limbs(M.to_limbs(x, L)) == x and M.limbs_from_be_bytes(M.be_bytes_from_limbs(x, L), L) == x
        checked += 1
        failed += not ok
    record("kernel identities (S1, S2, S6, M1-M9, M2', E1) against Python integers", checked, failed)


# ------------------------------------------------------------------ RFC text
def _rfc(rfc_dir, name):
    """The RFC text with its page furniture removed: the footer line ending in [Page N], the
    form feed, and the running header that follows it."""
    if not rfc_dir:
        return None
    path = os.path.join(rfc_dir, name)
    if not os.path.exists(path):
        return None
    out, after_ff = [], False
    for line in open(path, encoding="utf-8", errors="replace").read().split("\n"):
        if re.search(r"\[Page \d+\]\s*$", line):
            continue
        if line.startswith("\f"):
            after_ff = True
            continue
        if after_ff and line.startswith("RFC "):
            after_ff = False
            continue
        out.append(line)
    return "\n".join(out)


def rfc8017_constants(rfc_dir):
    text = _rfc(rfc_dir, "rfc8017.txt")
    if text is None:
        return record("RFC 8017 constants read from the RFC text", 0, 0, "rfc8017.txt not supplied")
    checked = failed = 0
    # section 9.2 note 1: "SHA-256: (0x)30 31 ... 04 20 || H."
    start = text.index("For the nine hash functions mentioned in Appendix B.1")
    block = text[start:text.index("2.  In version 1.5 of this document", start)]
    found = {}
    for m in re.finditer(r"([A-Z0-9/-]+):\s+\(0x\)((?:[0-9a-f]{2}\s+)+)\|\|\s*H\.", block):
        found[m.group(1)] = bytes.fromhex("".join(m.group(2).split()))
    for name in ("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256"):
        ok = name in found and found[name] == M.HASHES[name].digest_info_prefix
        checked += 1
        failed += not ok
    n_prefix = len(found)
    # section 7.1.1 notes: lHash for the empty label
    start = text.index("If L is the empty string, the corresponding hash value lHash")
    block = text[start:text.index("7.1.2.  Decryption Operation", start)]
    for m in re.finditer(r"(SHA-\d+):\s+\(0x\)((?:[0-9a-f]{8}\s+)+)", block):
        want = bytes.fromhex("".join(m.group(2).split()))
        ok = M.HASHES[m.group(1)].digest(b"") == want
        checked += 1
        failed += not ok
    record("RFC 8017 constants read from the RFC text (9.2 note 1 prefixes; 7.1.1 lHash)", checked, failed,
           f"{n_prefix} prefixes found in the text, 7 compared (MD2, MD5 not modelled)")


def rfc5869_vectors(rfc_dir):
    text = _rfc(rfc_dir, "rfc5869.txt")
    if text is None:
        return record("RFC 5869 appendix A test cases", 0, 0, "rfc5869.txt not supplied")
    cases = re.split(r"\nA\.\d\.\s+Test Case \d", text[text.index("Appendix A.  Test Vectors"):])[1:]
    checked = failed = 0
    for case in cases:
        hash_name = re.search(r"Hash = (SHA-\d+)", case).group(1).replace("-", "").lower()

        def field(name):
            lines = case.split("\n")
            for i, line in enumerate(lines):
                m = re.match(rf"\s+{name}\s*=\s*(.*)$", line)
                if not m:
                    continue
                raw = m.group(1)
                for cont in lines[i + 1:]:
                    if not cont.strip() or "=" in cont:
                        break
                    raw += " " + cont.strip()
                if raw.startswith("not provided"):
                    return None
                raw = re.sub(r"\(\d+ octets\)", "", raw).replace("0x", "")
                return bytes.fromhex("".join(raw.split()))
            raise KeyError(name)
        ikm, salt, info = field("IKM"), field("salt"), field("info")
        length = int(re.search(r"\n\s+L\s+=\s+(\d+)", case).group(1))
        prk, okm = field("PRK"), field("OKM")
        ok = M.hkdf_extract(hash_name, salt or b"", ikm) == prk
        ok &= M.hkdf(hash_name, salt or b"", ikm, info or b"", length) == okm and len(okm) == length
        checked += 1
        failed += not ok
    record("RFC 5869 appendix A test cases (HKDF extract and expand)", checked, failed)


# ------------------------------------------------------------------ Wycheproof
W_HASH = {"SHA-1": "SHA-1", "SHA-224": "SHA-224", "SHA-256": "SHA-256", "SHA-384": "SHA-384",
          "SHA-512": "SHA-512", "SHA-512/224": "SHA-512/224", "SHA-512/256": "SHA-512/256",
          "SHA3-224": "SHA3-224", "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384",
          "SHA3-512": "SHA3-512", "SHAKE128": "SHAKE128", "SHAKE256": "SHAKE256"}


def _wfiles(wdir, prefix):
    d = os.path.join(wdir, "testvectors_v1")
    return sorted(f for f in os.listdir(d) if f.startswith(prefix) and f.endswith("_test.json"))


def _pub(g, key="publicKey"):
    n, e = hi(g[key]["modulus"]), hi(g[key]["publicExponent"])
    k_len = g["keySize"] // 8

    class Pk:           # exponents above 32 bits appear in vectors; the model's math has no limit
        pass
    pk = Pk()
    pk.n, pk.e, pk.k_len = n, e, k_len
    return pk


def wycheproof(wdir):
    if not wdir or not os.path.isdir(os.path.join(wdir, "testvectors_v1")):
        for s in ("PKCS #1 v1.5 verify", "PKCS #1 v1.5 sign", "PSS verify", "OAEP decrypt"):
            record(f"Wycheproof {s}", 0, 0, "wycheproof checkout not supplied")
        return
    d = os.path.join(wdir, "testvectors_v1")

    # --- RSASSA-PKCS1-v1_5 verification
    checked = failed = acceptable = 0
    files = _wfiles(wdir, "rsa_signature_")
    for f in files:
        j = json.load(open(os.path.join(d, f)))
        for g in j["testGroups"]:
            pk, h = _pub(g), M.HASHES[W_HASH[g["sha"]]]
            for t in g["tests"]:
                strict = M.rsassa_pkcs1_v1_5_verify(pk, h, hx(t["msg"]), hx(t["sig"]))
                lenient = M.rsassa_pkcs1_v1_5_verify(pk, h, hx(t["msg"]), hx(t["sig"]), lenient_null=True)
                if t["result"] == "valid":
                    ok = strict and lenient
                elif t["result"] == "invalid":
                    ok = not strict and not lenient
                else:           # acceptable: only MissingNull is expected here
                    acceptable += 1
                    ok = t["flags"] == ["MissingNull"] and not strict and lenient
                checked += 1
                failed += not ok
    record("Wycheproof PKCS #1 v1.5 verify (rsa_signature_*)", checked, failed,
           f"{len(files)} files; {acceptable} 'acceptable' cases, all MissingNull: strict rejects, lenient accepts")

    # --- RSASSA-PKCS1-v1_5 signature generation (deterministic): s = EM^d mod n
    checked = failed = 0
    files = _wfiles(wdir, "rsa_pkcs1_")
    files = [f for f in files if f.endswith("_sig_gen_test.json")]
    for f in files:
        j = json.load(open(os.path.join(d, f)))
        for g in j["testGroups"]:
            k = g["privateKey"]
            n, dd, e = hi(k["modulus"]), hi(k["privateExponent"]), hi(k["publicExponent"])
            k_len, h = g["keySize"] // 8, M.HASHES[W_HASH[g["sha"]]]
            for t in g["tests"]:
                em = M.emsa_pkcs1_v1_5_encode_from_hash(h, h.digest(hx(t["msg"])), k_len)
                sig = M.i2osp(pow(M.os2ip(em), dd, n), k_len)
                ok = sig == hx(t["sig"]) and pow(M.os2ip(sig), e, n) == M.os2ip(em)
                checked += 1
                failed += not ok
    record("Wycheproof PKCS #1 v1.5 sign (rsa_pkcs1_*_sig_gen), (n, d) form", checked, failed, f"{len(files)} files")

    # --- RSASSA-PSS verification
    checked = failed = 0
    files = _wfiles(wdir, "rsa_pss_")
    skipped = []
    for f in files:
        j = json.load(open(os.path.join(d, f)))
        for g in j["testGroups"]:
            pk, h = _pub(g), M.HASHES[W_HASH[g["sha"]]]
            if g["mgf"] == "MGF1":
                mgf = M.Mgf("mgf1", M.HASHES[W_HASH[g["mgfSha"]]])
            elif g["mgf"] in ("SHAKE128", "SHAKE256"):
                mgf = M.Mgf("shake", M.HASHES[g["mgf"]])
            else:
                skipped.append((f, g["mgf"]))
                continue
            for t in g["tests"]:
                got = M.rsassa_pss_verify(pk, h, mgf, hx(t["msg"]), hx(t["sig"]), g["sLen"])
                ok = got == (t["result"] in ("valid", "acceptable"))
                checked += 1
                failed += not ok
    record("Wycheproof PSS verify (rsa_pss_*, incl. _params, _misc, SHAKE)", checked, failed,
           f"{len(files)} files" + (f"; skipped {skipped}" if skipped else ""))

    # --- RSAES-OAEP decryption (two-prime keys only)
    checked = failed = small = 0
    files = _wfiles(wdir, "rsa_oaep_")
    for f in files:
        j = json.load(open(os.path.join(d, f)))
        for g in j["testGroups"]:
            k = g["privateKey"]
            k_len = g["keySize"] // 8
            sk = M.PrivateComponents(hi(k["prime1"]), hi(k["prime2"]), hi(k["exponent1"]),
                                     hi(k["exponent2"]), hi(k["coefficient"]), k_len)
            assert sk.n == hi(k["modulus"]) and sk.h_key(hi(k["publicExponent"]))
            h = M.HASHES[W_HASH[g["sha"]]]
            mgf = M.Mgf("mgf1", M.HASHES[W_HASH[g["mgfSha"]]])
            for t in g["tests"]:
                # RFC 8017's range (c < n): Wycheproof is written against the RFC.
                got = M.rsaes_oaep_decrypt(sk, h, mgf, hx(t["label"]), hx(t["ct"]), sp80056b_range=False)
                narrow = M.rsaes_oaep_decrypt(sk, h, mgf, hx(t["label"]), hx(t["ct"]))
                if t["result"] == "valid":
                    ok = got == hx(t["msg"]) and narrow == got
                elif t["result"] == "acceptable":
                    # c in {0, 1}: a valid RFC 8017 decryption that SP 800-56B Rev. 2 refuses
                    small += 1
                    ok = ("SmallIntegerCiphertext" in t["flags"] and M.os2ip(hx(t["ct"])) in (0, 1)
                          and got == hx(t["msg"]) and narrow is None)
                else:
                    ok = got is None and narrow is None
                checked += 1
                failed += not ok
    record("Wycheproof OAEP decrypt (rsa_oaep_*), under RFC 8017's range and SP 800-56B's", checked, failed,
           f"{len(files)} files; the ranges differ on {small} 'acceptable' vectors (c = 0 or 1), as Wycheproof documents")


# ------------------------------------------------------------------ ACVP samples
A_HASH = {"SHA-1": "SHA-1", "SHA2-224": "SHA-224", "SHA2-256": "SHA-256", "SHA2-384": "SHA-384",
          "SHA2-512": "SHA-512", "SHA2-512/224": "SHA-512/224", "SHA2-512/256": "SHA-512/256",
          "SHA3-224": "SHA3-224", "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384",
          "SHA3-512": "SHA3-512", "SHAKE-128": "SHAKE128", "SHAKE-256": "SHAKE256"}


def _acvp(adir, name):
    p = os.path.join(adir, "gen-val", "json-files", name, "internalProjection.json")
    return json.load(open(p)) if os.path.exists(p) else None


def _acvp_verify(g, t):
    class Pk:
        pass
    pk = Pk()
    pk.n, pk.e, pk.k_len = hi(g["n"]), hi(g["e"]), g["modulo"] // 8
    h = M.HASHES[A_HASH[g["hashAlg"]]]
    msg, sig = hx(t["message"]), hx(t["signature"])
    if g["sigType"] == "pkcs1v1.5":
        return M.rsassa_pkcs1_v1_5_verify(pk, h, msg, sig)
    if g["sigType"] == "pss":
        mf = g.get("maskFunction") or "mgf1"          # FIPS186-2 groups carry no mask function
        mgf = M.Mgf("mgf1", h) if mf == "mgf1" else M.Mgf("shake", M.HASHES[A_HASH[mf.upper()]])
        return M.rsassa_pss_verify(pk, h, mgf, msg, sig, g["saltLen"])
    return None


def _sk_from(p, q, e, k_len):
    d_p, d_q, q_inv = pow(e, -1, p - 1), pow(e, -1, q - 1), pow(q, -1, p)
    return M.PrivateComponents(p, q, d_p, d_q, q_inv, k_len)


def acvp(adir):
    names = ["RSA sigGen FIPS186-5", "RSA sigVer FIPS186-5", "RSA sigVer FIPS186-2",
             "RSA signaturePrimitive 2.0", "RSA decryptionPrimitive Sp800-56Br2", "RSA keyGen FIPS186-5",
             "KAS-IFC-SSC Sp800-56Br2", "KTS-IFC Sp800-56Br2"]
    if not adir or not os.path.isdir(os.path.join(adir, "gen-val", "json-files")):
        for s in names:
            record(f"ACVP sample {s}", 0, 0, "ACVP-Server checkout not supplied")
        return

    j = _acvp(adir, "RSA-SigGen-FIPS186-5")
    checked = failed = skipped = 0
    for g in j["testGroups"]:
        for t in g["tests"]:
            if g.get("conformance") == "SP800-106":       # randomized message hashing
                skipped += 1
                continue
            checked += 1
            failed += _acvp_verify(g, t) is not True
    record("ACVP sample RSA sigGen FIPS186-5: the server's signatures verify", checked, failed,
           f"{skipped} tests under the SP 800-106 conformance (randomized hashing) not modelled")

    for name, label in (("RSA-SigVer-FIPS186-5", "FIPS186-5"), ("RSA-SigVer-FIPS186-2", "FIPS186-2")):
        j = _acvp(adir, name)
        checked = failed = skipped = 0
        for g in j["testGroups"]:
            for t in g["tests"]:
                got = _acvp_verify(g, t)
                if got is None:
                    skipped += 1
                    continue
                checked += 1
                failed += got != t["testPassed"]
        record(f"ACVP sample RSA sigVer {label}: verdict equals testPassed", checked, failed,
               f"{skipped} ANS X9.31 tests not modelled" if skipped else "")

    for name, label, in_key, out_key in (
            ("RSA-SignaturePrimitive-2.0", "signaturePrimitive 2.0", "message", "signature"),
            ("RSA-DecryptionPrimitive-Sp800-56Br2", "decryptionPrimitive Sp800-56Br2", "ct", "pt")):
        j = _acvp(adir, name)
        checked = failed = 0
        for g in j["testGroups"]:
            k_len = g["modulo"] // 8
            for t in g["tests"]:
                n, e, p, q = hi(t["n"]), hi(t["e"]), hi(t["p"]), hi(t["q"])
                sk = _sk_from(p, q, e, k_len)
                x = hi(t[in_key])
                ok = sk.n == n and sk.h_key(e)
                if t["dmp1"]:
                    ok &= (sk.d_p, sk.d_q, sk.q_inv) == (hi(t["dmp1"]), hi(t["dmq1"]), hi(t["iqmp"]))
                if "Decryption" in name:
                    in_range = M.in_open_range(x, n)          # SP 800-56B Rev. 2 RSADP [extraction]
                else:
                    in_range = 0 <= x < n                     # RFC 8017 RSASP1 step 1
                ok &= in_range == t["testPassed"]
                if in_range:
                    y = sk.crt_exp(x)
                    ok &= y == hi(t[out_key]) and pow(y, e, n) == x
                    if t["d"]:
                        ok &= y == pow(x, hi(t["d"]), n)
                checked += 1
                failed += not ok
        record(f"ACVP sample RSA {label}: CRT result, range verdict", checked, failed)

    j = _acvp(adir, "RSA-KeyGen-FIPS186-5")
    checked = failed = 0
    for g in j["testGroups"]:
        for t in g["tests"]:
            n, e, p, q = hi(t["n"]), hi(t["e"]), hi(t["p"]), hi(t["q"])
            sk = _sk_from(p, q, e, g["modulo"] // 8)
            ok = sk.n == n and (sk.d_p, sk.d_q, sk.q_inv) == (hi(t["dmp1"]), hi(t["dmq1"]), hi(t["iqmp"]))
            ok &= M.check_a11_criteria(g["modulo"], e, p, q, hi(t["d"]) or None) == []
            checked += 1
            failed += not ok
    record("ACVP sample RSA keyGen FIPS186-5: n, dP, dQ, qInv recomputed; A.1.1 criteria hold", checked, failed)

    j = _acvp(adir, "KAS-IFC-SSC-Sp800-56Br2")
    checked = failed = 0
    for g in j["testGroups"]:
        k_len = g["modulo"] // 8
        for t in g["tests"]:
            keys = {}
            for who in ("iut", "server"):
                if t.get(who + "P"):
                    keys[who] = _sk_from(hi(t[who + "P"]), hi(t[who + "Q"]), hi(t[who + "E"]), k_len)
                    assert keys[who].n == hi(t[who + "N"])
            parts, consistent = {}, True
            # <who>C is what <who> sent: it decrypts under the other party's key to <who>Z.
            for who, other in (("iut", "server"), ("server", "iut")):
                if t.get(who + "C") and other in keys:
                    parts[who] = M.rsasve_recover(keys[other], hx(t[who + "C"]))
                    consistent &= parts[who] == hx(t[who + "Z"])
                elif t.get(who + "Z"):
                    parts[who] = hx(t[who + "Z"])
            first, second = ("iut", "server") if g["kasRole"] == "initiator" else ("server", "iut")
            z_full = parts.get(first, b"") + (parts.get(second, b"") if g["scheme"] == "KAS2" else b"")
            ok = (z_full == hx(t["z"])) == t["testPassed"]
            if t["testPassed"]:
                ok &= consistent
            checked += 1
            failed += not ok
    record("ACVP sample KAS-IFC-SSC: RSASVE.RECOVER gives Z; z verdict equals testPassed", checked, failed)

    j = _acvp(adir, "KTS-IFC-Sp800-56Br2")
    checked = failed = skipped = 0
    for g in j["testGroups"]:
        k_len, cfg = g["modulo"] // 8, g["ktsConfiguration"]
        h = M.HASHES[A_HASH[cfg["hashAlg"]]]
        for t in g["tests"]:
            if cfg["associatedDataPattern"]:
                skipped += 1          # the associated-data encoding is WP12's to model
                continue
            who, ct_key, k_key = ("server", "iutC", "iutK") if g["kasRole"] == "initiator" else ("iut", "serverC", "serverK")
            sk = _sk_from(hi(t[who + "P"]), hi(t[who + "Q"]), hi(t[who + "E"]), k_len)
            got = M.rsaes_oaep_decrypt(sk, h, M.Mgf("mgf1", h), b"", hx(t[ct_key]))
            checked += 1
            failed += got != hx(t[k_key])
    record("ACVP sample KTS-IFC: RSA-OAEP decryption recovers the transported key", checked, failed,
           f"{skipped} tests with associated data not modelled yet")


# ------------------------------------------------------------------ model against itself
def schemes_round_trip(wdir):
    """Encode/decode and sign/verify round trips over the parameter space, on a real 2048-bit
    key taken from a Wycheproof OAEP file (so the key is not the model's own)."""
    path = os.path.join(wdir or "", "testvectors_v1", "rsa_oaep_2048_sha256_mgf1sha256_test.json")
    if not os.path.exists(path):
        return record("scheme round trips over the parameter space", 0, 0, "needs a Wycheproof key")
    k = json.load(open(path))["testGroups"][0]["privateKey"]
    sk = M.PrivateComponents(hi(k["prime1"]), hi(k["prime2"]), hi(k["exponent1"]),
                             hi(k["exponent2"]), hi(k["coefficient"]), 256)
    e, d = hi(k["publicExponent"]), hi(k["privateExponent"])
    pk = M.PublicComponents(sk.n, e, 256)
    rnd = random.Random(7)
    checked = failed = 0
    for m in (0, 1, 2, sk.n - 1, sk.p, sk.q, 5 * sk.p, rnd.randrange(sk.n)):          # C1
        s = sk.crt_exp(m)
        ok = s == pow(m, d, sk.n) and pow(s, e, sk.n) == m
        checked += 1
        failed += not ok
    s1_fault = (pow(7 % sk.p, sk.d_p, sk.p) + 1) % sk.p                                # C6
    s2 = pow(7 % sk.q, sk.d_q, sk.q)
    s_bad = s2 + sk.q * (((s1_fault - s2) * sk.q_inv) % sk.p)
    ok = math.gcd((pow(s_bad, e, sk.n) - 7) % sk.n, sk.n) == sk.q
    checked += 1
    failed += not ok
    names = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256",
             "SHA3-256", "SHA3-512", "SHAKE128", "SHAKE256"]
    for hn in names:
        h = M.HASHES[hn]
        msg = rnd.randbytes(rnd.randrange(0, 200))
        for mgf in ([M.Mgf("mgf1", M.HASHES[x]) for x in ("SHA-1", "SHA-256", "SHA-512")]
                    + [M.Mgf("shake", M.HASHES["SHAKE128"]), M.Mgf("shake", M.HASHES["SHAKE256"])]):
            for s_len in (0, 1, 20, h.out_len, 64, 256 - h.out_len - 2):
                salt = rnd.randbytes(s_len)
                sig = M.rsassa_pss_sign(sk, h, mgf, msg, salt)
                ok = M.rsassa_pss_verify(pk, h, mgf, msg, sig, s_len)
                ok &= not M.rsassa_pss_verify(pk, h, mgf, msg + b"x", sig, s_len)
                if s_len + 1 <= 256 - h.out_len - 2:
                    ok &= not M.rsassa_pss_verify(pk, h, mgf, msg, sig, s_len + 1)
                checked += 1
                failed += not ok
        if h.digest_info_prefix:
            sig = M.rsassa_pkcs1_v1_5_sign(sk, h, msg)
            ok = M.rsassa_pkcs1_v1_5_verify(pk, h, msg, sig) and not M.rsassa_pkcs1_v1_5_verify(pk, h, msg + b"x", sig)
            # the absent-NULL encoding: accepted by the lenient verifier only
            alt = M.emsa_pkcs1_v1_5_encode_from_hash(h, h.digest(msg), 256, t=M.digest_info_absent_null(h, h.digest(msg)))
            sig_alt = M.i2osp(sk.crt_exp(M.os2ip(alt)), 256)
            ok &= not M.rsassa_pkcs1_v1_5_verify(pk, h, msg, sig_alt)
            ok &= M.rsassa_pkcs1_v1_5_verify(pk, h, msg, sig_alt, lenient_null=True)
            checked += 1
            failed += not ok
    for hn in ("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256"):
        h = M.HASHES[hn]
        for mn in ("SHA-1", "SHA-256", "SHA-512"):
            mgf = M.Mgf("mgf1", M.HASHES[mn])
            for m_len in (0, 1, 32, 256 - 2 * h.out_len - 2):
                msg, label, seed = rnd.randbytes(m_len), rnd.randbytes(rnd.randrange(0, 40)), rnd.randbytes(h.out_len)
                ct = M.rsaes_oaep_encrypt(pk, h, mgf, label, msg, seed)
                ok = M.rsaes_oaep_decrypt(sk, h, mgf, label, ct) == msg
                ok &= M.rsaes_oaep_decrypt(sk, h, mgf, label + b"x", ct) is None
                checked += 1
                failed += not ok
            try:
                M.eme_oaep_encode(h, mgf, b"", b"\x00" * h.out_len, b"\x00" * (256 - 2 * h.out_len - 1), 256)
                failed += 1
            except M.ModelError:
                pass
            checked += 1
    rng = M.StreamRng(rnd.randbytes(256 * 8))                                            # RSASVE
    z, c = M.rsasve_generate(pk, rng)
    ok = M.rsasve_recover(sk, c) == z and M.in_open_range(M.os2ip(z), sk.n)
    ok &= len(M.rsasve_hkdf_derive("sha256", b"salt", z, b"info", 42)) == 42
    for bad in (0, 1, sk.n - 1, sk.n):
        try:
            M.rsasve_recover(sk, M.i2osp(bad, 256))
            ok = False
        except M.ModelError:
            pass
    checked += 1
    failed += not ok
    record("scheme round trips over the parameter space (PSS, v1.5, OAEP, RSASVE), C1, C6", checked, failed)


def keygen_model():
    """The key-generation model at small widths: outputs meet the definitions it is built from."""
    rnd = random.Random(99)
    checked = failed = 0
    for HALF in (2, 4, 8):
        for _ in range(6 if HALF < 8 else 3):
            stream = rnd.randbytes(1 << 20)
            pk, sk = M.keygen_from_rng(M.StreamRng(stream), 5, 112, HALF)
            p, q, nlen = sk.p, sk.q, 128 * HALF
            lcm = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
            ok = pk.n == p * q and pk.n.bit_length() == nlen and sk.h_key(65537)
            ok &= _is_prime(p) and _is_prime(q)
            ok &= p >> (64 * HALF - 2) == 3 and q >> (64 * HALF - 2) == 3
            ok &= sk.d_p == pow(65537, -1, lcm) % (p - 1) and sk.q_inv == pow(q, -1, p)   # K8, K9
            # at HALF = 1 the |p-q| bound is vacuous (64 - 100 < 0); HALF >= 2 exercises it
            ok &= M.check_a11_criteria(nlen, 65537, p, q) == []
            # same stream, same key: the model is a function of the stream
            pk2, sk2 = M.keygen_from_rng(M.StreamRng(stream), 5, 112, HALF)
            ok &= (pk2.n, sk2.p, sk2.q) == (pk.n, p, q)
            checked += 1
            failed += not ok
    # is_probable_prime on known primes and composites (values are standard: Mersenne primes,
    # Carmichael numbers 561 = 3*11*17 and 41041 = 7*11*13*41, a product of two primes)
    rng = M.StreamRng(rnd.randbytes(1 << 18))
    cases = [(2, True), (3, True), (561, False), (41041, False), ((1 << 61) - 1, True),
             ((1 << 127) - 1, True), ((1 << 521) - 1, True), (((1 << 61) - 1) * ((1 << 89) - 1), False),
             (1, False), (0, False), (4, False), (1021, True), (1023, False), (1048573, True), (1048575, False)]
    for w, want in cases:
        N = max(1, -(-w.bit_length() // 64))
        checked += 1
        failed += M.is_probable_prime(w, 5, rng, N) != want
    # failure paths
    for stream, strength, kind in ((b"", 256, "RNG_ERROR"), (b"\x00" * 64, 0, "RNG_STRENGTH"),
                                   (b"\xff" * 16, 256, "RNG_ERROR")):
        try:
            M.keygen_from_rng(M.StreamRng(stream, strength), 5, 112, 2)
            failed += 1
        except M.ModelError as err:
            failed += err.kind != kind
        checked += 1
    record("key-generation model at 256/512/1024-bit moduli: primes, criteria, determinism, errors", checked, failed)


def _is_prime(n):
    """Deterministic trial division up to 2^20 then 40 fixed-base Miller-Rabin rounds: an
    independent check of the small model outputs (not a proof for large n)."""
    if n < 2:
        return False
    for p in M.SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in M.SMALL_PRIMES[:40]:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


# ------------------------------------------------------------------ the crate layer (WP14.3)
def crate_layer():
    """Section 10 of the model against facts that do not come from it: arithmetic written out
    here, the plan's statements of I1, C7 to C9, E11 and K16, and the specification layer
    that the sections above have already tested."""
    rnd = random.Random(20261122)
    checked = failed = 0

    def chk(cond):
        nonlocal checked, failed
        checked += 1
        failed += not cond

    def raises(kind, fn, text=None):
        try:
            fn()
        except M.ModelError as err:
            return err.kind == kind and (text is None or err.detail == text)
        return False

    # M11: square and multiply written out, against the model's value; e = 0 gives 1.
    for L in (1, 2, 4):
        for _ in range(40):
            n = rnd.getrandbits(64 * L) | 1 | (1 << (64 * L - 1))
            ctx = M.MontgomeryContext.for_secret_modulus(n, L)
            pub = M.MontgomeryContext.for_public_modulus(n, L)
            chk((ctx.modulus, ctx.n_prime, ctx.r_mod_n, ctx.r2_mod_n)
                == (pub.modulus, pub.n_prime, pub.r_mod_n, pub.r2_mod_n))            # M12
            base = rnd.choice([0, 1, n - 1, rnd.getrandbits(64 * L)])
            e = rnd.choice([0, 1, 2, 3, 65537, (1 << 32) + 1, (1 << 56) - 1, M.BETA - 1, rnd.getrandbits(64)])
            acc = 1
            for bit in bin(e)[2:] if e else "":
                acc = acc * acc % n
                if bit == "1":
                    acc = acc * base % n
            chk(M.mod_pow_public_exponent(base, e, ctx) == acc)
            chk(M.public_exp(n, e, base, L) == acc)
    for bad in (0, 2, 4):
        try:
            M.MontgomeryContext.for_secret_modulus(bad, 1)
            chk(False)
        except M.ContractError:
            chk(True)
    chk(M.MontgomeryContext.for_public_modulus(4, 1) is None)

    # A small key with every property checked by hand arithmetic: 64-bit primes.
    e = 65537
    while True:
        p = rnd.getrandbits(64) | 1 | (3 << 62)
        q = rnd.getrandbits(64) | 1 | (3 << 62)
        if p != q and _is_prime(p) and _is_prime(q) and (p - 1) % e and (q - 1) % e:
            break
    n, k_len = p * q, 16
    d = pow(e, -1, math.lcm(p - 1, q - 1))
    d_p, d_q, q_inv = d % (p - 1), d % (q - 1), pow(q, -1, p)
    sk = M.key_private_new(p, q, d_p, d_q, q_inv, e, k_len)
    pk = M.key_public_new(n, e, k_len)
    chk(sk.h_key() and sk.e == e and sk.n == n and n.bit_length() == 128)

    # C8: under H_key the check passes for every x < n, x sharing a factor with n included,
    # and what is released is x^d mod n. C7: for x >= n the answer is (False, 0).
    for x in [0, 1, 2, n - 1, p, q, (5 * p) % n, (7 * q) % n] + [rnd.randrange(n) for _ in range(60)]:
        ok, y = M.crt_exp_checked(p, q, d_p, d_q, q_inv, n, e, x, 2, 1)
        chk(ok and y == pow(x, d, n) and pow(y, e, n) == x)
        chk(M.rsasp1_checked(sk, x) == pow(x, d, n))
    for x in (n, n + 1, (1 << 128) - 1):
        chk(M.crt_exp_checked(p, q, d_p, d_q, q_inv, n, e, x, 2, 1) == (False, 0))
        chk(raises("DECODING", lambda x=x: M.rsasp1_checked(sk, x)))

    # C9: a damaged component. The verdict is exactly "y^e == x"; where it is False nothing of
    # y is returned. Under a sound key a wrong half-result is never released (injectivity).
    for which in range(3):
        for _ in range(40):
            parts = [d_p, d_q, q_inv]
            parts[which] ^= 1 << rnd.randrange(60)
            if not (parts[0] < p and parts[1] < q and parts[2] < p):
                continue
            x = rnd.randrange(n)
            ok, y = M.crt_exp_checked(p, q, parts[0], parts[1], parts[2], n, e, x, 2, 1)
            raw = M.crt_exp(p, q, parts[0], parts[1], parts[2], x, 2, 1)
            chk(ok == (pow(raw, e, n) == x) and y == (raw if ok else 0))
            chk(not ok or raw == pow(x, d, n))
    # C9: a foreign odd exponent. 0, 1 and n - 1 pass whatever it is; the plan says so, and
    # the reason is that x^d is x for those three and each is its own odd power.
    for e2 in (3, 5, 17, 257, 65539, (1 << 32) + 1, M.BETA - 1):
        for x in (0, 1, n - 1):
            chk(M.crt_exp_checked(p, q, d_p, d_q, q_inv, n, e2, x, 2, 1) == (True, x))
        passed = sum(M.crt_exp_checked(p, q, d_p, d_q, q_inv, n, e2, x, 2, 1)[0]
                     for x in (rnd.randrange(2, n - 1) for _ in range(200)))
        chk(passed == 0)          # a random x passing would need x^(d*e2) = x: about 2^-60 here

    # C9, the pass set of a foreign exponent, counted. For a sound key and an exponent e2 in
    # place of e, x passes exactly when x^(d*e2) = x mod p and mod q; modulo a prime r that
    # has 1 + gcd(e2 - e, r - 1) solutions (zero, and the roots of unity of that order, d
    # being a unit modulo r - 1). So the set has (1 + gcd(e2-e, p-1)) * (1 + gcd(e2-e, q-1))
    # elements: at least nine for odd e2, the residues 0, 1, -1 modulo each prime combined.
    # By exhaustion over a key small enough to try every x.
    for sp, sq in ((239, 233), (509, 503), (1019, 947)):
        se = 5
        if (sp - 1) % se == 0 or (sq - 1) % se == 0:
            continue
        sn, sd = sp * sq, pow(se, -1, math.lcm(sp - 1, sq - 1))
        sdp, sdq, sqi = sd % (sp - 1), sd % (sq - 1), pow(sq, -1, sp)
        for e2 in (3, 7, 11, 17, 65537):
            count = sum(pow(M.crt_exp(sp, sq, sdp, sdq, sqi, x, 2, 1), e2, sn) == x for x in range(sn))
            want = (1 + math.gcd(e2 - se, sp - 1)) * (1 + math.gcd(e2 - se, sq - 1))
            chk(count == want and count >= 9)
        nine = {x for x in range(sn) if x % sp in (0, 1, sp - 1) and x % sq in (0, 1, sq - 1)}
        chk(len(nine) == 9 and all(pow(M.crt_exp(sp, sq, sdp, sdq, sqi, x, 2, 1), 3, sn) == x for x in nine))

    # I1 against the constructors: the predicate and the ordered checks give one verdict.
    def verdict(fn):
        try:
            fn()
            return True
        except M.ModelError:
            return False
    for _ in range(600):
        nn = rnd.choice([n, n - 1, n >> 1, (n >> 1) | 1, 1, 3, (1 << 127) + 1, (1 << 127) - 1, (1 << 128) - 1,
                         rnd.getrandbits(128), rnd.getrandbits(128) | 1 | (1 << 127)])
        ee = rnd.choice([0, 1, 2, 3, 4, 65535, 65536, 65537, (1 << 32) + 1, M.BETA - 1, rnd.getrandbits(64)])
        chk(verdict(lambda: M.key_public_new(nn, ee, k_len)) == M.i1_public(nn, ee, 128))
        chk(verdict(lambda: M.kem_public_new(nn, ee, k_len)) == (M.i1_public(nn, ee, 128) and ee >= 65537))
        pp = rnd.choice([p, p - 1, q, 1, 3, (1 << 63) + 1, (1 << 62) + 1, rnd.getrandbits(64) | 1])
        qq = rnd.choice([q, q - 1, p, 1, 5, (1 << 63) + 3, (1 << 61) + 1, rnd.getrandbits(64) | 1])
        dd = [rnd.choice([0, 1, v - 1, v, v + 1, rnd.getrandbits(64)]) % (1 << 64) for v in (pp, qq, pp)]
        want = M.i1_private(pp, qq, dd[0], dd[1], dd[2], ee, 128)
        chk(verdict(lambda: M.key_private_new(pp, qq, dd[0], dd[1], dd[2], ee, k_len)) == want)
        chk(verdict(lambda: M.kem_private_new(pp, qq, dd[0], dd[1], dd[2], ee, k_len)) == (want and ee >= 65537))
    # I1's consequence, checked on what the predicate accepts: both primes have exactly h bits.
    for _ in range(4000):
        pp, qq = rnd.getrandbits(64) | 1, rnd.getrandbits(rnd.choice([64, 64, 63, 60, 33])) | 1
        if M.i1_private(pp, qq, 0, 0, 0, 3, 128):
            chk(pp.bit_length() == 64 and qq.bit_length() == 64 and qq < 2 * pp and pp < 2 * qq)
    # the first-pass shapes are refused now, each with the text about the top bit
    chk(raises("DECODING", lambda: M.key_public_new((1 << 60) | 1, 65537, k_len), M.MSG_N_SHORT))
    chk(raises("DECODING", lambda: M.key_private_new(3, 5, 1, 1, 2, 65537, k_len), M.MSG_N_SHORT))
    chk(raises("DECODING", lambda: M.key_private_new(1, 3, 0, 1, 0, 65537, k_len), M.MSG_N_SHORT))
    chk(raises("DECODING", lambda: M.key_private_new(p, q, d_p, d_q, q_inv, 4, k_len), M.MSG_E))
    chk(raises("DECODING", lambda: M.kem_private_new(p, q, d_p, d_q, q_inv, 3, k_len), M.MSG_KEM_E))

    # I2: the encodings, their lengths, and decoding as the inverse.
    chk(len(pk.encode()) == k_len + 8 and len(sk.encode()) == 5 * k_len // 2 + 8)
    chk(pk.encode() == n.to_bytes(16, "big") + e.to_bytes(8, "big"))
    chk(sk.encode() == b"".join(v.to_bytes(8, "big") for v in (p, q, d_p, d_q, q_inv, e)))
    back = M.key_private_decode(sk.encode(), k_len)
    chk((back.p, back.q, back.d_p, back.d_q, back.q_inv, back.e) == (p, q, d_p, d_q, q_inv, e))
    chk(M.key_public_decode(pk.encode(), k_len).n == n)
    chk(raises("KEY_LENGTH", lambda: M.key_public_decode(pk.encode()[:-4], k_len)))   # the old layout
    chk(raises("KEY_LENGTH", lambda: M.key_private_decode(sk.encode()[:-8], k_len)))

    # E11: the length rules, with the specification layer as the judge of the right lengths.
    sha256, sha512 = M.HASHES["SHA-256"], M.HASHES["SHA-512"]
    mgf = M.Mgf("mgf1", sha256)
    h32, s32 = rnd.randbytes(32), rnd.randbytes(32)
    for bad in (0, 1, 31, 33, 64, 65, 130, 4096):
        chk(raises("LENGTH", lambda: M.crate_emsa_v15_encode(sha256, bytes(bad), 256), M.MSG_HASH_LEN))
        chk(raises("LENGTH", lambda: M.crate_emsa_pss_encode(sha256, mgf, bytes(bad), s32, 32, 256), M.MSG_HASH_LEN))
        chk(raises("LENGTH", lambda: M.crate_emsa_pss_encode(sha256, mgf, h32, bytes(bad), 32, 256), M.MSG_SALT_LEN))
        chk(M.crate_emsa_v15_verify(sha256, bytes(bad), bytes(256)) is False)
        chk(M.crate_emsa_pss_verify(sha256, mgf, bytes(bad), bytes(256), 32) is False)
    # the hash's length is judged before the salt's
    chk(raises("LENGTH", lambda: M.crate_emsa_pss_encode(sha256, mgf, bytes(5), bytes(5), 32, 256), M.MSG_HASH_LEN))
    em = M.crate_emsa_pss_encode(sha256, mgf, h32, s32, 32, 256)
    chk(em == M.emsa_pss_encode_from_hash(sha256, mgf, h32, s32, 2047) and M.crate_emsa_pss_verify(sha256, mgf, h32, em, 32))
    chk(M.crate_emsa_v15_encode(sha256, h32, 256) == M.emsa_pkcs1_v1_5_encode_from_hash(sha256, h32, 256))
    # RFC 8017 section 9.1.1 step 3 at its boundary: emLen 128, hLen 64, sLen 62 fits, 63 does not.
    mgf512, h64 = M.Mgf("mgf1", sha512), rnd.randbytes(64)
    chk(len(M.crate_emsa_pss_encode(sha512, mgf512, h64, bytes(62), 62, 128)) == 128)
    chk(raises("ENCODING", lambda: M.crate_emsa_pss_encode(sha512, mgf512, h64, bytes(63), 63, 128)))
    chk(M.crate_emsa_pss_verify(sha512, mgf512, h64, bytes(128), 63) is False)
    # sign_from_hash: nothing is drawn when the hash's length is wrong; one draw otherwise
    rng = M.StreamRng(bytes(64))
    chk(raises("LENGTH", lambda: M.crate_sign_from_hash_pss_rng(None, sha256, mgf, bytes(20), 32, rng)) and rng.calls == 0)

    # K16
    for length in (0, 1, 8, 64):
        for claim in (None, 0, 1, length - 1, length, length + 1, 4096):
            chk(M.fill_bytes(length, claim) == (claim == length))
    record("crate layer (I1, I2, C7-C9, M11, M12, E11, K16)", checked, failed)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rfc")
    ap.add_argument("--wycheproof")
    ap.add_argument("--acvp")
    ap.add_argument("--require-all", action="store_true")
    a = ap.parse_args()
    kernel()
    rfc8017_constants(a.rfc)
    rfc5869_vectors(a.rfc)
    wycheproof(a.wycheproof)
    acvp(a.acvp)
    schemes_round_trip(a.wycheproof)
    keygen_model()
    crate_layer()
    total = sum(r[1] for r in RESULTS)
    failed = sum(r[2] for r in RESULTS)
    skipped = [r[0] for r in RESULTS if r[1] == 0]
    print(f"TOTAL: {total} checks in {len(RESULTS)} sections, {failed} failed, {len(skipped)} sections skipped")
    bad = failed > 0 or (a.require_all and skipped)
    print("SELFTEST FAILED" if bad else "SELFTEST PASSED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
