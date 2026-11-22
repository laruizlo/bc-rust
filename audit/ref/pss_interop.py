#!/usr/bin/env python3
"""RSASSA-PSS in both directions against the model and OpenSSL, at full-length moduli:
finding F-02, row (d) of plan WP14.4 (obligation E6).

    python3 -I audit/ref/pss_interop.py --runner audit/harness/target/release/diff_runner \
            --deps <pip --target dir with cryptography> [--scale 1.0] [--sizes 2048,3072,...]
            [--seed N] [--keep DIR] [--no-floor]

Finding F-02: a signature key type held a modulus of any length, and the crate's RSASSA-PSS,
which fixes emBits at 8 * K_LEN - 1, then neither signed nor verified as RFC 8017 section 8.1
does. Since e395060 a key's modulus has exactly its size's bit length (plan I1), which is the
hypothesis under which the fixed emBits is the RFC's (plan E6). The first pass's probe showed
the failure on a 2044-bit modulus; that key is refused now. This run shows the other half: with
every modulus the constructors admit -- the least and the greatest of a size among them -- the
crate and two independent implementations agree, each way.

  A  The crate signs under a salt this script chose: through the one-shot signing role, with
     an RNG that holds the salt and nothing else, and through `sign_from_hash_with_salt`.
     Each signature must be the model's byte for byte (RFC 8017 section 8.1.1 with the same
     salt), verify under the model's section 8.1.2, and verify under OpenSSL.
  B  OpenSSL signs, with salts of its own drawing, and the model signs, with salts from this
     script. The crate must verify each: through the one-shot verifying role and through
     `verify_from_hash`. At RSA-1024 and RSA-1536, where the crate only verifies, this is
     the whole test.

Controls, since a judge that cannot fail proves nothing. On A: one bit of the crate's
signature flipped, one bit of the message flipped -- the model and OpenSSL must refuse both.
On B: one bit of a signature flipped, one bit of the message flipped, and the signature
offered under another parameter set of the same size -- the crate must refuse all three.

Keys are made here from a seed, not by either implementation: per size the least modulus the
constructors admit (two primes just above 2^(h - 1/2), so n is 2^(2h-1) plus a little), the
greatest (the two largest primes below 2^h), and primes with their top two bits set as the
crate's generator makes them, under e = 65537 and under other exponents (3, 2^32 + 1, a
56-bit one, 2^64 - 1). OpenSSL takes them as numbers; a key it will not load is reported, and
its cells then rest on the model alone and do not count toward the floor.

The floor (at scale 1.0 with the four signing sizes): 256 signatures of the crate verified by
both the model and OpenSSL; 256 of OpenSSL's and 256 of the model's verified by the crate.
"""
import argparse
import math
import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rsa_ref as M  # noqa: E402

SIGNING_SIZES = (2048, 3072, 4096, 8192)
VERIFY_ONLY_SIZES = (1024, 1536)

# tag (as diff_runner names the Rust type), message hash, mask kind, mask hash, sLen, and
# whether the PyPI binding of OpenSSL offers the pairing (it has no SHAKE-as-MGF PSS).
ALGS = (
    ("sha256", "SHA-256", "mgf1", "SHA-256", 32, True),
    ("sha384", "SHA-384", "mgf1", "SHA-384", 48, True),
    ("sha512", "SHA-512", "mgf1", "SHA-512", 64, True),
    ("sha3_256", "SHA3-256", "mgf1", "SHA3-256", 32, True),
    ("sha512_mgf1sha256_32", "SHA-512", "mgf1", "SHA-256", 32, True),
    ("sha256_mgf1sha1_20", "SHA-256", "mgf1", "SHA-1", 20, True),
    ("sha256_nosalt", "SHA-256", "mgf1", "SHA-256", 0, True),
    ("shake128", "SHAKE128", "shake", "SHAKE128", 32, False),
    ("shake256", "SHAKE256", "shake", "SHAKE256", 64, False),
)
# the parameter set a signature is offered under in the cross-parameter control
OTHER = {"sha256": "sha256_nosalt", "sha256_nosalt": "sha256", "sha384": "sha256", "sha512": "sha512_mgf1sha256_32",
         "sha512_mgf1sha256_32": "sha512", "sha3_256": "sha256", "sha256_mgf1sha1_20": "sha256",
         "shake128": "sha256", "shake256": "sha512"}
MESSAGES_PER_CELL = {1024: 4, 1536: 4, 2048: 8, 3072: 4, 4096: 4, 8192: 2}
FLOOR = 256


# ------------------------------------------------------------------ primes and keys
_SMALL = [p for p in range(3, 4000, 2) if all(p % d for d in range(3, int(p ** 0.5) + 1, 2))]
_PRIMORIAL = math.prod(_SMALL)


def is_prime(n, rnd):
    if n < 4000:
        return n == 2 or n in _SMALL
    if n % 2 == 0 or math.gcd(n, _PRIMORIAL) != 1:
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in [2] + [rnd.randrange(3, n - 1) for _ in range(15)]:
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


def prime_from(start, step, e, rnd, avoid=()):
    """The first prime at or after `start` in steps of `step` (+2 or -2) with gcd(e, p-1) = 1."""
    p = start | 1
    while not (p not in avoid and math.gcd(e, p - 1) == 1 and is_prime(p, rnd)):
        p += step
    return p


def make_key(bits, shape, e, rnd):
    h = bits // 2
    if shape == "least":
        # the least n >= 2^(2h-1) this search reaches: both primes just above 2^(h - 1/2)
        p = prime_from(math.isqrt(1 << (2 * h - 1)) + 1, 2, e, rnd)
        q = prime_from(p + 2, 2, e, rnd)
    elif shape == "greatest":
        p = prime_from((1 << h) - 1, -2, e, rnd)
        q = prime_from(p - 2, -2, e, rnd)
    else:                                   # as the crate's generator shapes them: top two bits set
        p = prime_from(rnd.getrandbits(h) | (3 << (h - 2)), 2, e, rnd)
        q = prime_from(rnd.getrandbits(h) | (3 << (h - 2)), 2, e, rnd, avoid=(p,))
    n = p * q
    assert n.bit_length() == bits and p.bit_length() == q.bit_length() == h and p != q
    k_len = bits // 8
    sk = M.PrivateComponents(p, q, pow(e, -1, p - 1), pow(e, -1, q - 1), pow(q, -1, p), k_len, e)
    assert sk.h_key() and M.i1_private(sk.p, sk.q, sk.d_p, sk.d_q, sk.q_inv, e, bits) and M.i1_public(n, e, bits)
    return {"bits": bits, "shape": shape, "e": e, "sk": sk, "pk": M.PublicComponents(n, e, k_len),
            "d": pow(e, -1, math.lcm(p - 1, q - 1)), "margin": (n - (1 << (bits - 1))).bit_length()}


KEY_PLAN = {
    1024: (("least", 65537), ("greatest", 65537)),
    1536: (("random", 65537),),
    2048: (("least", 65537), ("greatest", 65537), ("random", 65537), ("random", 3), ("random", (1 << 64) - 1)),
    3072: (("least", 65537), ("greatest", 65537), ("random", (1 << 32) + 1)),
    4096: (("least", 65537), ("random", (1 << 56) - 5)),
    8192: (("random", 65537),),
}


# ------------------------------------------------------------------ OpenSSL
class OpenSsl:
    def __init__(self, deps):
        sys.path.insert(0, deps)
        import cryptography
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.backends.openssl import backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
        self.rsa, self.padding, self.utils, self.InvalidSignature = rsa, padding, utils, InvalidSignature
        self.H = {"SHA-1": hashes.SHA1, "SHA-256": hashes.SHA256, "SHA-384": hashes.SHA384,
                  "SHA-512": hashes.SHA512, "SHA3-256": hashes.SHA3_256}
        self.version = f"cryptography {cryptography.__version__}, {backend.openssl_version_text()}"

    def load(self, key):
        sk, pk = key["sk"], key["pk"]
        pub = self.rsa.RSAPublicNumbers(pk.e, pk.n)
        return self.rsa.RSAPrivateNumbers(sk.p, sk.q, key["d"], sk.d_p, sk.d_q, sk.q_inv, pub).private_key()

    def pad(self, alg):
        _tag, _h, _kind, mgf_hash, s_len, _ = alg
        return self.padding.PSS(mgf=self.padding.MGF1(self.H[mgf_hash]()), salt_length=s_len)

    def sign(self, priv, alg, msg):
        return priv.sign(msg, self.pad(alg), self.H[alg[1]]())

    def verify(self, priv, alg, msg, sig, digest=None):
        """True or False; over the message, or over `digest` as a prehash."""
        h = self.H[alg[1]]()
        try:
            if digest is None:
                priv.public_key().verify(sig, msg, self.pad(alg), h)
            else:
                priv.public_key().verify(sig, digest, self.pad(alg), self.utils.Prehashed(h))
            return True
        except self.InvalidSignature:
            return False


# ------------------------------------------------------------------ the run
def flip(data, bit):
    b = bytearray(data)
    b[(bit // 8) % len(b)] ^= 1 << (bit % 8)
    return bytes(b)


def model_parts(alg):
    _tag, h_name, kind, mgf_hash, s_len, _ = alg
    return M.HASHES[h_name], M.Mgf(kind, M.HASHES[mgf_hash]), s_len


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runner", required=True)
    ap.add_argument("--deps", help="a `pip install --target` directory holding cryptography; without it OpenSSL takes no part and the run fails its floor")
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--sizes", default=",".join(map(str, VERIFY_ONLY_SIZES + SIGNING_SIZES)))
    ap.add_argument("--seed", type=int, default=20261122)
    ap.add_argument("--keep")
    ap.add_argument("--no-floor", action="store_true", help="do not require the 256 of each kind (a reduced run)")
    a = ap.parse_args()
    sizes = [int(s) for s in a.sizes.split(",")]
    rnd = random.Random(a.seed)
    ossl = OpenSsl(a.deps) if a.deps else None

    t0 = time.time()
    keys, notes = [], []
    for bits in sizes:
        for shape, e in KEY_PLAN[bits]:
            key = make_key(bits, shape, e, rnd)
            key["ossl"] = None
            if ossl:
                try:
                    key["ossl"] = ossl.load(key)
                except Exception as err:        # reported, never silent
                    notes.append(f"OpenSSL would not load the RSA-{bits} {shape} key with e = {e:#x}: {type(err).__name__}: {err}")
            keys.append(key)
    key_s = time.time() - t0

    cases = []      # (id, line, kind, payload)
    def add(line, kind, **payload):
        cases.append((len(cases) + 1, line, kind, payload))

    cells = {}      # (bits, tag) -> counters

    def cell(bits, tag):
        return cells.setdefault((bits, tag), dict.fromkeys(
            ("signed", "equal", "model_ok", "ossl_ok", "oracle_refusals", "oracle_controls",
             "from_ossl", "from_model", "from_ossl_ok", "from_model_ok", "crate_refusals", "crate_controls"), 0))

    for key in keys:
        bits, sk, pk = key["bits"], key["sk"], key["pk"]
        k_len = bits // 8
        n_msgs = max(1, round(a.scale * MESSAGES_PER_CELL[bits]))
        for alg in ALGS:
            tag, _h, _kind, _mh, s_len, has_ossl = alg
            h, mgf, _ = model_parts(alg)
            if k_len < h.out_len + s_len + 2:           # RFC 8017 section 9.1.1 step 3: not a pairing
                continue
            priv = key["ossl"] if has_ossl else None
            head = f"BITS={bits} alg={tag}"
            for i in range(n_msgs):
                msg = rnd.randbytes(rnd.choice([0, 1, 55, 56, 64, 119, 1000]) if i else 3)
                digest = h.digest(msg)
                salt = (b"\x00" * s_len, b"\xff" * s_len)[i] if i < 2 else rnd.randbytes(s_len)
                via = ("role", "hash")[i % 2]
                data = f"msg={M_hex(msg)}" if via == "role" else f"hash={digest.hex()}"
                # A: the crate signs
                if bits in SIGNING_SIZES:
                    want = M.rsassa_pss_sign(sk, h, mgf, msg, salt)
                    tail = [f"calls=1", f"consumed={s_len}"] if via == "role" and s_len else []
                    add(f"pss_sign {head} via={via} sk={sk.encode().hex()} {data} salt={M_hex(salt)}", "sign",
                        key=key, alg=alg, msg=msg, digest=digest, want=[want.hex()] + tail, control=i == 0)
                # B: the others sign, the crate verifies
                signed = [("model", M.rsassa_pss_sign(sk, h, mgf, msg, rnd.randbytes(s_len)))]
                if priv is not None:
                    try:
                        signed.append(("ossl", ossl.sign(priv, alg, msg)))
                    except Exception as err:
                        notes.append(f"OpenSSL would not sign at RSA-{bits} with {tag}: {type(err).__name__}: {err}")
                        priv = None
                for who, sig in signed:
                    if not M.rsassa_pss_verify(pk, h, mgf, msg, sig, s_len):
                        notes.append(f"ORACLES DISAGREE: the model refuses a signature of {who} at RSA-{bits}, {tag}")
                    line = f"pss_verify {head} via={via} pk={pk.encode().hex()} {data} sig={sig.hex()}"
                    add(line, "verify", bits=bits, tag=tag, who=who, want_valid=True)
                    if i == 0:
                        bit = rnd.randrange(8 * k_len)
                        add(f"pss_verify {head} via={via} pk={pk.encode().hex()} {data} sig={flip(sig, bit).hex()}",
                            "verify", bits=bits, tag=tag, who=who, want_valid=False)
                        other_msg = flip(msg, rnd.randrange(8 * len(msg)))
                        other = f"msg={M_hex(other_msg)}" if via == "role" else f"hash={h.digest(other_msg).hex()}"
                        add(f"pss_verify {head} via={via} pk={pk.encode().hex()} {other} sig={sig.hex()}",
                            "verify", bits=bits, tag=tag, who=who, want_valid=False)
                        o_alg = next(x for x in ALGS if x[0] == OTHER[tag])
                        oh = M.HASHES[o_alg[1]]
                        if k_len >= oh.out_len + o_alg[4] + 2:
                            o_data = f"msg={M_hex(msg)}" if via == "role" else f"hash={oh.digest(msg).hex()}"
                            add(f"pss_verify BITS={bits} alg={o_alg[0]} via={via} pk={pk.encode().hex()} {o_data} sig={sig.hex()}",
                                "verify", bits=bits, tag=tag, who=who, want_valid=False)

    text = "".join(f"{cid} {line}\n" for cid, line, _k, _p in cases)
    if a.keep:
        os.makedirs(a.keep, exist_ok=True)
        open(os.path.join(a.keep, "pss-interop-cases.txt"), "w").write(text)
    t0 = time.time()
    proc = subprocess.run([a.runner], input=text.encode(), capture_output=True)
    run_s = time.time() - t0
    out = proc.stdout.decode()
    if a.keep:
        open(os.path.join(a.keep, "pss-interop-results.txt"), "w").write(out)
    results = {int(l.split()[0]): l.split()[1:] for l in out.splitlines() if l.strip()}

    problems = []
    for cid, line, kind, p in cases:
        got = results.get(cid)
        where = " ".join(line.split()[:4])
        if got is None or got[0] in ("PANIC", "HARNESS"):
            problems.append(f"case {cid} ({where}): {got}")
            continue
        if kind == "sign":
            key, alg = p["key"], p["alg"]
            c = cell(key["bits"], alg[0])
            h, mgf, s_len = model_parts(alg)
            c["signed"] += 1
            if got[0] != "OK" or got[1:] != p["want"]:
                problems.append(f"case {cid} ({where}): the crate's signature is not the model's: {' '.join(got)[:120]}")
                continue
            c["equal"] += 1
            sig = bytes.fromhex(got[1])
            if M.rsassa_pss_verify(key["pk"], h, mgf, p["msg"], sig, s_len):
                c["model_ok"] += 1
            else:
                problems.append(f"case {cid} ({where}): the model refuses the crate's signature")
            priv = key["ossl"] if alg[5] else None
            if priv is not None:
                if ossl.verify(priv, alg, p["msg"], sig) and ossl.verify(priv, alg, None, sig, digest=p["digest"]):
                    c["ossl_ok"] += 1
                else:
                    problems.append(f"case {cid} ({where}): OpenSSL refuses the crate's signature")
            if p["control"]:
                bad_sig, bad_msg = flip(sig, rnd.randrange(8 * len(sig))), flip(p["msg"], rnd.randrange(8 * len(p["msg"])))
                verdicts = [M.rsassa_pss_verify(key["pk"], h, mgf, p["msg"], bad_sig, s_len),
                            M.rsassa_pss_verify(key["pk"], h, mgf, bad_msg, sig, s_len)]
                if priv is not None:
                    verdicts += [ossl.verify(priv, alg, p["msg"], bad_sig), ossl.verify(priv, alg, bad_msg, sig)]
                c["oracle_controls"] += len(verdicts)
                c["oracle_refusals"] += verdicts.count(False)
                if any(verdicts):
                    problems.append(f"case {cid} ({where}): an oracle accepted an altered signature or message")
        else:
            c = cell(p["bits"], p["tag"])
            valid = got == ["OK", "VALID"]
            if p["want_valid"]:
                c["from_" + p["who"]] += 1
                if valid:
                    c[f"from_{p['who']}_ok"] += 1
                else:
                    problems.append(f"case {cid} ({where}): the crate refuses a signature of {p['who']}: {' '.join(got)[:100]}")
            else:
                c["crate_controls"] += 1
                if got[0] == "ERR":
                    c["crate_refusals"] += 1
                else:
                    problems.append(f"case {cid} ({where}): the crate accepted an altered signature, message or parameter set")

    print(f"PSS interop: seed={a.seed} scale={a.scale} sizes={a.sizes} cases={len(cases)} "
          f"(keys in {key_s:.1f}s, runner in {run_s:.1f}s, exit {proc.returncode})")
    print(f"OpenSSL: {ossl.version if ossl else 'not used (no --deps)'}")
    print("keys: " + "; ".join(
        f"RSA-{k['bits']} {k['shape']} e={k['e']:#x}" + (f" (n = 2^{k['bits'] - 1} + a {k['margin']}-bit number)" if k["shape"] == "least" else "")
        + ("" if k["ossl"] is not None or not ossl else " [not loaded by OpenSSL]") for k in keys))
    print(f"\n{'size':>5} {'parameters':22s} | {'crate signs':>11} {'= model':>8} {'model ok':>8} {'OpenSSL ok':>10} {'oracles refuse':>15}"
          f" | {'OpenSSL->crate':>14} {'model->crate':>12} {'crate refuses':>14}")
    tot = dict.fromkeys(("signed", "equal", "model_ok", "ossl_ok", "both", "from_ossl_ok", "from_model_ok"), 0)
    for (bits, tag), c in sorted(cells.items(), key=lambda kv: (kv[0][0], [x[0] for x in ALGS].index(kv[0][1]))):
        print(f"{bits:>5} {tag:22s} | {c['signed']:>11} {c['equal']:>8} {c['model_ok']:>8} {c['ossl_ok']:>10} "
              f"{c['oracle_refusals']:>7}/{c['oracle_controls']:<7} | {c['from_ossl_ok']:>6}/{c['from_ossl']:<7} "
              f"{c['from_model_ok']:>5}/{c['from_model']:<6} {c['crate_refusals']:>6}/{c['crate_controls']:<7}")
        for k in ("signed", "equal", "model_ok", "ossl_ok", "from_ossl_ok", "from_model_ok"):
            tot[k] += c[k]
        tot["both"] += min(c["model_ok"], c["ossl_ok"])
    controls = (sum(c["oracle_refusals"] for c in cells.values()), sum(c["oracle_controls"] for c in cells.values()),
                sum(c["crate_refusals"] for c in cells.values()), sum(c["crate_controls"] for c in cells.values()))
    print(f"\nA  the crate signed {tot['signed']}: {tot['equal']} equal to the model's byte for byte, {tot['model_ok']} verified by "
          f"the model, {tot['ossl_ok']} by OpenSSL ({tot['both']} by both)")
    print(f"B  the crate verified {tot['from_ossl_ok']} signatures of OpenSSL and {tot['from_model_ok']} of the model")
    print(f"controls: the oracles refused {controls[0]} of {controls[1]} altered inputs; the crate refused {controls[2]} of {controls[3]}")
    for note in sorted(set(notes)):
        print("note:", note)
    for line in problems[:30]:
        print("PROBLEM", line)
    floor_met = all(tot[k] >= FLOOR for k in ("both", "from_ossl_ok", "from_model_ok"))
    if not a.no_floor:
        print(f"floor ({FLOOR} of each kind): {'met' if floor_met else 'NOT met'}")
    bad = (problems or proc.returncode != 0 or controls[1] == 0 or controls[3] == 0
           or any("ORACLES DISAGREE" in n for n in notes) or (not a.no_floor and not floor_met))
    print("\nPSS INTEROP FAILED" if bad else "\nPSS INTEROP PASSED")
    return 1 if bad else 0


def M_hex(b):
    return b.hex() if b else "-"


if __name__ == "__main__":
    sys.exit(main())
