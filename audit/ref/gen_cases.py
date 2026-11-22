#!/usr/bin/env python3
"""Differential run: the Rust kernel and key generation against rsa_ref.py.

    python3 -I audit/ref/gen_cases.py --runner audit/harness/target/release/diff_runner \
            --profile release [--scale 1.0] [--seed N] [--ops a,b,...] [--keep DIR]

Writes the cases, runs `diff_runner`, and judges every result line against the model.

Families (plan section 5.4). Carried over from WP0 and adapted to the code at the pin:
substrate, modexp, rsa_core, leakage, keygen_helpers, primality_and_keygen. New in WP14.3:
constructors (I1, I2), public_exponent (M11), checked_crt (C7 to C9), from_hash_lengths (E11),
rng_draws (K16).

Verdicts
  match        the Rust output equals the model's
  MISMATCH     it does not: a finding, or a model error, to be settled by hand
  PANIC        the Rust code panicked where the model has a value
  expected     a documented debug assertion fired in a debug build (mod_pow's `base < modulus`)
  observation  the input is outside the model's contract (ContractError); the Rust result is
               listed, not judged. These are the designed out-of-contract probes.

`--profile` must say how the runner was built: a debug build has the crate's debug assertions
on, and one of them is narrower than the proof obligation it guards (mod_pow, M9 / O2).
"""
import argparse
import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rsa_ref as M  # noqa: E402

WIDTHS = (1, 2, 3, 4, 8, 16, 24, 32, 48, 64, 128)
HALVES = (1, 2, 4, 8, 16, 24, 32, 64)
REDUCE_PAIRS = ((1, 1), (2, 1), (3, 1), (1, 2), (2, 2), (4, 2), (4, 3), (1, 4), (4, 4), (8, 4),
                (8, 8), (16, 8), (16, 16), (32, 16), (24, 24), (48, 24), (32, 32), (64, 32),
                (64, 64), (128, 64))


def hl(x, L):
    return f"{x:0{16 * L}x}"


def hb(b):
    return b.hex() if b else "-"


class Gen:
    def __init__(self, seed, scale, profile):
        self.rnd = random.Random(seed)
        self.scale, self.profile = scale, profile
        self.cases = []          # (id, op, args, expectation)
        self.keys = {}           # (HALF, shape) -> sound keys already generated

    def n(self, base, L=1, cost=0):
        """How many random cases: `base`, cut down where one call costs about L^3 limb
        multiplications (an exponentiation), never below two."""
        cut = max(1.0, (L / 16) ** 3) if cost >= 3 else 1.0
        return max(2, int(self.scale * base / cut))

    def add(self, op, args, expect):
        self.cases.append((len(self.cases) + 1, op, args, expect))

    def call(self, op, args, fn, fmt, on_error=None):
        """Expectation from the model: fmt(fn()) or an observation when out of contract.
        `on_error`: the tokens that follow the error tag when the model predicts an error."""
        try:
            self.add(op, args, ("OK", fmt(fn())))
        except M.ContractError as err:
            self.add(op, args, ("OBSERVE", str(err)))
        except M.ModelError as err:
            kind = ERR_KINDS.get((err.kind, err.detail), err.kind)
            self.add(op, args, ("ERR", kind) if on_error is None else ("ERR", kind, list(on_error)))

    def key(self, HALF, shape=None):
        """A sound CRT key with e = 65537 at HALF limbs per prime: (p, q, dP, dQ, qInv, n).
        `shape` is the pair of prime bit lengths; the default is two primes of full length
        with their top two bits set, which is what the constructors admit (I1). Keys are kept:
        a 4096-bit prime takes Python a while."""
        h = 64 * HALF
        shape = shape or (h, h)
        pool = self.keys.setdefault((HALF, shape), [])
        if not pool or (len(pool) < 2 and HALF <= 16):
            e = 65537
            while True:
                p, q = self.prime(shape[0], top2=shape[0] == h), self.prime(shape[1], top2=shape[1] == h)
                if p != q and (p - 1) % e and (q - 1) % e:
                    break
            pool.append((p, q, pow(e, -1, p - 1), pow(e, -1, q - 1), pow(q, -1, p), p * q))
        return self.rnd.choice(pool)

    # ---- value pools
    def val(self, L):
        Rr, r = M.R(L), self.rnd
        pick = r.random()
        if pick < 0.25:
            return r.choice([0, 1, 2, Rr - 1, Rr - 2, Rr >> 1, (Rr >> 1) - 1, (Rr >> 1) + 1,
                             M.BETA - 1 if L > 1 else 1, Rr - M.BETA if L > 1 else 0])
        if pick < 0.35:                               # sparse: a few set or cleared limbs
            x = 0 if r.random() < 0.5 else Rr - 1
            for _ in range(r.randrange(1, 3)):
                x ^= r.getrandbits(64) << (64 * r.randrange(L))
            return x % Rr
        if pick < 0.45:                               # short: top limbs zero
            return r.getrandbits(64 * r.randrange(1, L + 1))
        return r.getrandbits(64 * L)

    def odd_mod(self, L, minimum=3):
        Rr, r = M.R(L), self.rnd
        pick = r.random()
        if pick < 0.2:
            c = [3, 5, Rr - 1, (Rr >> 1) + 1, Rr - 3, (1 << (64 * L - 1)) - 1]
            if L > 1:
                c += [M.BETA + 1, M.R(L - 1) - 1, M.R(L - 1) + 1]      # top limb zero or one
            n = r.choice(c)
        elif pick < 0.3:
            n = r.getrandbits(64 * r.randrange(1, L + 1)) | 1         # short modulus
        else:
            n = r.getrandbits(64 * L) | 1
            if r.random() < 0.5:
                n |= 1 << (64 * L - 1)
        return max(n | 1, minimum)

    def prime(self, bits, top2=False):
        r = self.rnd
        while True:
            p = r.getrandbits(bits) | 1 | (1 << (bits - 1))
            if top2:
                p |= 1 << (bits - 2)
            if _is_prime(p):
                return p


def _is_prime(n):
    if n < 2:
        return False
    for p in M.SMALL_PRIMES[:60]:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in M.SMALL_PRIMES[:24]:
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


# The crate's errors as the judge compares them: (model kind, model detail) -> tag.
ERR_KINDS = {
    ("LENGTH", M.MSG_HASH_LEN): "LENGTH_HASH",
    ("LENGTH", M.MSG_SALT_LEN): "LENGTH_SALT",
    ("ENCODING", M.MSG_PSS_TOO_SHORT): "ENCODING",
}


# ------------------------------------------------------------------ case families
def substrate(g):
    for L in WIDTHS:
        Rr = M.R(L)
        for _ in range(g.n(300)):
            a, b = g.val(L), g.val(L)
            A = {"L": L, "a": hl(a, L), "b": hl(b, L)}
            for op, fn in (("nat_add", M.nat_add), ("nat_sub", M.nat_sub),
                           ("nat_add_assign", M.nat_add), ("nat_sub_assign", M.nat_sub)):
                g.call(op, A, lambda fn=fn: fn(a, b, L), lambda v: [hl(v[0], L), f"{v[1]:x}"])
            g.call("nat_is_zero", {"L": L, "a": hl(a, L)}, lambda: M.nat_is_zero(a, L), lambda v: [str(int(v))])
        g.call("nat_is_zero", {"L": L, "a": hl(0, L)}, lambda: True, lambda v: ["1"])
        for _ in range(g.n(200, L, 1)):
            a, b = g.val(L), g.val(L)
            A = {"L": L, "a": hl(a, L), "b": hl(b, L)}
            g.call("widening_mul", A, lambda: M.widening_mul(a, b, L), lambda v: [hl(v, 2 * L)])
            g.call("widening_mul_into", A, lambda: M.widening_mul(a, b, L), lambda v: [hl(v, 2 * L)])
            g.call("widening_square", {"L": L, "a": hl(a, L)}, lambda: M.widening_square(a, L), lambda v: [hl(v, 2 * L)])
        for a in (0, 1, Rr - 1, Rr >> 1, (Rr >> 1) + 1):      # S5's all-ones and doubling edges
            g.call("widening_square", {"L": L, "a": hl(a, L)}, lambda a=a: M.widening_square(a, L), lambda v: [hl(v, 2 * L)])
        for _ in range(g.n(200, L, 1)):
            n = g.odd_mod(L)
            np_ = M.mont_n_prime(n % M.BETA)
            for T in (0, n * Rr - 1, (n - 1) ** 2, (Rr - 1) * (n - 1), g.rnd.randrange(n * Rr)):
                g.call("redc", {"L": L, "t": hl(T, 2 * L), "n": hl(n, L), "np": f"{np_:x}"},
                       lambda T=T: M.redc(T, n, np_, L), lambda v: [hl(v[0], L), f"{v[1]:x}"])


def modexp(g):
    for n0 in [1, 3, M.BETA - 1, (M.BETA >> 1) + 1] + [g.rnd.getrandbits(64) | 1 for _ in range(g.n(500))]:
        g.call("mont_n_prime", {"n0": f"{n0:x}"}, lambda n0=n0: M.mont_n_prime(n0), lambda v: [f"{v:016x}"])
    for L in WIDTHS:
        Rr = M.R(L)
        fields = lambda c: ["NONE"] if c is None else [hl(c.modulus, L), f"{c.n_prime:016x}", hl(c.r_mod_n, L), hl(c.r2_mod_n, L)]
        # M12: both constructors against one model context. The public one refuses an even
        # modulus; the secret one tests nothing, so an even modulus is outside its contract
        # (an observation: a debug build stops at mont_n_prime's assertion, a release build
        # returns a context). n = 1 is the N4 probe on both.
        for n in [0, 2, 4, Rr - 2, 1]:
            g.call("ctx_public", {"L": L, "n": hl(n, L)}, lambda n=n: M.MontgomeryContext.for_public_modulus(n, L), fields)
            g.call("ctx_secret", {"L": L, "n": hl(n, L)}, lambda n=n: M.MontgomeryContext.for_secret_modulus(n, L), fields)
        edge = [3, Rr - 1, (1 << (64 * L - 1)) + 1] + ([M.R(L - 1) - 1, M.R(L - 1) + 1] if L > 1 else [])
        for n in edge + [g.odd_mod(L) for _ in range(g.n(60, L, 2))]:
            g.call("ctx_public", {"L": L, "n": hl(n, L)}, lambda n=n: M.MontgomeryContext.for_public_modulus(n, L), fields)
            g.call("ctx_secret", {"L": L, "n": hl(n, L)}, lambda n=n: M.MontgomeryContext.for_secret_modulus(n, L), fields)
        for _ in range(g.n(300, L, 1)):
            n = g.odd_mod(L)
            a = g.rnd.randrange(n)
            g.call("double_mod_n_vartime", {"L": L, "a": hl(a, L), "n": hl(n, L)}, lambda: M.double_mod_n(a, n, L), lambda v: [hl(v, L)])
        # M2 and M2c: one value from the branching chain and from the masked one, for odd
        # moduli and for even ones above 1 (neither proof uses oddness).
        for bits in (0, 1, 63, 64, 65, 64 * L, 128 * L):
            for n in (g.odd_mod(L), g.odd_mod(L), max(2, g.val(L) & ~1), Rr - 2, 2):
                A = {"L": L, "bits": bits, "n": hl(n, L)}
                g.call("pow2_mod_vartime", A, lambda n=n: M.pow2_mod_vartime(bits, n, L), lambda v: [hl(v, L)])
                g.call("pow2_ct", A, lambda n=n: M.pow2_mod_ct(bits, n, L), lambda v: [hl(v, L)])
        for _ in range(g.n(200, L, 1)):
            n = g.odd_mod(L)
            np_ = M.mont_n_prime(n % M.BETA)
            ctx = M.MontgomeryContext.for_public_modulus(n, L)
            a, b, x = g.rnd.randrange(n), g.rnd.randrange(n), g.val(L)
            T = g.rnd.choice([0, n * Rr - 1, (n - 1) ** 2, (Rr - 1) * (n - 1), g.rnd.randrange(n * Rr)])
            N = {"L": L, "n": hl(n, L), "np": f"{np_:x}"}
            g.call("redc_normalize", {**N, "t": hl(T, 2 * L)}, lambda: M.redc_normalize(T, n, np_, L), lambda v: [hl(v, L)])
            g.call("mont_mul", {**N, "a": hl(a, L), "b": hl(b, L)}, lambda: M.mont_mul(a, b, n, np_, L), lambda v: [hl(v, L)])
            g.call("mont_square", {**N, "a": hl(a, L)}, lambda: M.mont_square(a, n, np_, L), lambda v: [hl(v, L)])
            g.call("to_montgomery", {"L": L, "n": hl(n, L), "a": hl(x, L)}, lambda: M.to_montgomery(x, ctx), lambda v: [hl(v, L)])
            g.call("from_montgomery", {"L": L, "n": hl(n, L), "a": hl(x, L)}, lambda: M.from_montgomery(x, ctx), lambda v: [hl(v, L)])
            g.call("mul_mod", {"L": L, "n": hl(n, L), "a": hl(x, L), "b": hl(b, L)}, lambda: M.mul_mod(x, b, ctx), lambda v: [hl(v, L)])
        for _ in range(g.n(300)):
            m = max(1, g.val(L))                             # any modulus, odd or even (M6-M8)
            a, b = g.rnd.randrange(m), g.rnd.randrange(m)
            g.call("sub_mod", {"L": L, "a": hl(a, L), "b": hl(b, L), "m": hl(m, L)}, lambda: M.sub_mod(a, b, m, L), lambda v: [hl(v, L)])
            for bit in (0, 1):
                g.call("ct_shift_in_bit_mod", {"L": L, "acc": hl(a, L), "bit": bit, "m": hl(m, L)},
                       lambda bit=bit: M.ct_shift_in_bit_mod(a, bit, m, L), lambda v: [hl(v, L)])
            x, y, mask = g.val(L), g.val(L), g.rnd.randrange(2)
            g.add("ct_select_array", {"L": L, "mask": mask, "a": hl(x, L), "b": hl(y, L)}, ("OK", [hl(x if mask else y, L)]))
            g.add("ct_swap_array", {"L": L, "mask": mask, "a": hl(x, L), "b": hl(y, L)},
                  ("OK", [hl(y, L), hl(x, L)] if mask else [hl(x, L), hl(y, L)]))
        for m in (1, 2, Rr - 1, Rr - 2, Rr >> 1):            # M7's boundary moduli
            for acc in sorted({0, m - 1, m // 2}):
                for bit in (0, 1):
                    g.call("ct_shift_in_bit_mod", {"L": L, "acc": hl(acc, L), "bit": bit, "m": hl(m, L)},
                           lambda acc=acc, bit=bit, m=m: M.ct_shift_in_bit_mod(acc, bit, m, L), lambda v: [hl(v, L)])
        # M9: exponents 0, 1, R-1 and bases 0, 1, n-1, and bases >= n (O2)
        for _ in range(g.n(120, L, 3)):
            n = g.odd_mod(L)
            ctx = M.MontgomeryContext.for_public_modulus(n, L)
            base = g.rnd.choice([0, 1, n - 1, g.rnd.randrange(n), g.rnd.randrange(n)])
            exp = g.rnd.choice([0, 1, 2, Rr - 1, g.val(L), g.val(L)])
            g.call("mod_pow", {"L": L, "base": hl(base, L), "exp": hl(exp, L), "n": hl(n, L)},
                   lambda: M.mod_pow(base, exp, ctx), lambda v: [hl(v, L)])
        for _ in range(g.n(24, L, 3)):
            n = g.odd_mod(L)
            if n >= Rr - 1:
                continue
            ctx = M.MontgomeryContext.for_public_modulus(n, L)
            base = g.rnd.choice([n, n + 1, Rr - 1, g.rnd.randrange(n, Rr)])
            exp = g.rnd.choice([0, 1, 3, Rr - 1, g.val(L)])
            args = {"L": L, "base": hl(base, L), "exp": hl(exp, L), "n": hl(n, L)}
            if g.profile == "debug":
                g.add("mod_pow", args, ("EXPECTED_PANIC", "mod_pow_needs_base_<_modulus"))
            else:
                g.call("mod_pow", args, lambda: M.mod_pow(base, exp, ctx), lambda v: [hl(v, L)])
    for WIDE, NARROW in REDUCE_PAIRS:
        for _ in range(g.n(120)):
            v = g.val(WIDE)
            m = max(1, g.val(NARROW))
            g.call("reduce_wide", {"WIDE": WIDE, "NARROW": NARROW, "v": hl(v, WIDE), "m": hl(m, NARROW)},
                   lambda: M.reduce_wide(v, m, WIDE, NARROW), lambda x: [hl(x, NARROW)])


def rsa_core(g):
    for L in WIDTHS:
        for _ in range(g.n(40, L, 3)):
            n = g.odd_mod(L)
            e = g.rnd.choice([3, 5, 17, 65537, 0xFFFFFFFF, g.rnd.getrandbits(32) | 1, (1 << 32) + 1,
                              M.BETA - 1, g.rnd.getrandbits(64) | 1])
            x = g.rnd.choice([0, 1, n - 1, g.rnd.randrange(n)])
            g.call("public_exp", {"L": L, "n": hl(n, L), "e": f"{e:x}", "x": hl(x, L)},
                   lambda: M.public_exp(n, e, x, L), lambda v: [hl(v, L)])
        if L in (1, 2, 4, 16, 32, 128):
            x = g.rnd.getrandbits(64 * L)
            g.add("codec", {"L": L, "x": x.to_bytes(8 * L, "big").hex()}, ("OK", [hl(x, L), x.to_bytes(8 * L, "big").hex()]))
    e = 65537
    for HALF in HALVES:
        L, h = 2 * HALF, 64 * HALF
        A = lambda p, q, dp, dq, qi, m: {"HALF": HALF, "p": hl(p, HALF), "q": hl(q, HALF), "dp": hl(dp, HALF),
                                         "dq": hl(dq, HALF), "qinv": hl(qi, HALF), "m": hl(m, L)}
        # valid keys: balanced, unbalanced, a prime with its top limb zero. Since the response
        # the constructors refuse all but the first shape (I1): the others still run on
        # crt_exp itself, which is unchanged, through the harness.
        shapes = [(h, h), (h, h)]
        if HALF <= 32:
            shapes += [(h - 24, h), (h, h - 37)] + ([(h - 64, h)] if HALF > 1 else [])
        for bp, bq in shapes[: max(2, g.n(5, HALF, 3) + 1)]:
            p, q, dp, dq, qi, n = g.key(HALF, (bp, bq))
            ms = [0, 1, 2, n - 1, p, q, (5 * p) % n, (7 * q) % n, g.rnd.randrange(n), g.rnd.randrange(n)]
            for m in ms[: max(3, g.n(10, HALF, 3) + 2)]:
                g.call("crt_exp", A(p, q, dp, dq, qi, m), lambda m=m: M.crt_exp(p, q, dp, dq, qi, m, L, HALF), lambda v: [hl(v, L)])
        # malformed keys the constructor admits (C3): composite or tiny "primes", arbitrary exponents
        Rh = M.R(HALF)
        pool = [1, 3, 5, 9, 15, 21, Rh - 1, Rh - 3, (Rh >> 1) + 1] + [g.rnd.randrange(1, Rh) | 1 for _ in range(12)]
        for _ in range(max(4, g.n(40, HALF, 3))):
            p, q = g.rnd.choice(pool), g.rnd.choice(pool)
            if p == q:
                continue
            dp, dq, qi = g.rnd.randrange(p), g.rnd.randrange(q), g.rnd.randrange(p)
            n = p * q
            m = g.rnd.choice([0, 1, max(n - 1, 0), g.rnd.randrange(n), g.rnd.randrange(M.R(L))])
            g.call("crt_exp", A(p, q, dp, dq, qi, m), lambda: M.crt_exp(p, q, dp, dq, qi, m, L, HALF), lambda v: [hl(v, L)])


def keygen_helpers(g):
    e = M.PUBLIC_EXPONENT
    for r in [1, 2, e - 1, e - 2] + [g.rnd.randrange(1, e) for _ in range(g.n(300))]:
        g.call("inv_mod_u64_prime", {"r": f"{r:x}", "e": f"{e:x}"}, lambda r=r: M.inv_mod_u64_prime(r, e), lambda v: [f"{v:x}"])
    for L in WIDTHS:
        Rr = M.R(L)
        for _ in range(g.n(200)):
            a, m = g.val(L), g.rnd.choice([1, 2, 3, e, M.BETA - 1, g.rnd.getrandbits(64) | 1, g.rnd.getrandbits(32) + 1])
            g.call("mod_u64", {"L": L, "a": hl(a, L), "m": f"{m:x}"}, lambda: M.mod_u64(a, m), lambda v: [f"{v:x}"])
            k, add = g.rnd.getrandbits(64), g.rnd.getrandbits(64)
            g.call("mul_u64_add", {"L": L, "a": hl(a, L), "k": f"{k:x}", "add": f"{add:x}"},
                   lambda: M.mul_u64_add(a, k, add, L), lambda v: [hl(v[0], L), f"{v[1]:x}"])
            d = g.rnd.getrandbits(64) | 1
            hi = g.rnd.randrange(d)
            g.call("div_u64", {"L": L, "hi": f"{hi:x}", "a": hl(a, L), "d": f"{d:x}"},
                   lambda: M.div_u64(hi, a, d, L), lambda v: [hl(v[0], L), f"{v[1]:x}"])
            s = g.rnd.choice([0, 1, 63, 64, 65, 64 * L - 1, g.rnd.randrange(64 * L)])
            g.add("shl", {"L": L, "a": hl(a, L), "s": s}, ("OK", [hl((a << s) % Rr, L)]))
            g.add("shr", {"L": L, "a": hl(a, L), "s": s}, ("OK", [hl(a >> s, L)]))
            tz = 64 * L if a == 0 else (a & -a).bit_length() - 1
            g.add("zeros", {"L": L, "a": hl(a, L)}, ("OK", [str(tz), str(64 * L - a.bit_length())]))
        for _ in range(g.n(120, L, 2)):
            a, b = g.val(L), g.val(L)
            if g.rnd.random() < 0.5:                         # share a large factor
                f = g.rnd.getrandbits(g.rnd.randrange(1, 32 * L + 1)) | 1
                a, b = (a // f) * f % Rr, (b // f) * f % Rr
            g.call("gcd", {"L": L, "a": hl(a, L), "b": hl(b, L)}, lambda: M.gcd(a, b, L), lambda v: [hl(v, L)])
            d = max(1, g.val(L))
            g.call("div", {"L": L, "a": hl(a, L), "d": hl(d, L)}, lambda: M.div(a, d, L), lambda v: [hl(v, L)])
        for a, b in ((0, 0), (0, 5), (5, 0), (Rr - 1, Rr - 1), (Rr >> 1, Rr >> 1), (1, Rr - 1)):
            g.call("gcd", {"L": L, "a": hl(a, L), "b": hl(b, L)}, lambda a=a, b=b: M.gcd(a, b, L), lambda v: [hl(v, L)])
        for _ in range(g.n(120, L, 1)):
            m = g.rnd.getrandbits(64 * L) | (1 << 40)
            if m % e == 0:
                continue
            g.call("inverse_of_e_mod", {"L": L, "m": hl(m, L)}, lambda: M.inverse_of_e_mod(m, L), lambda v: [hl(v, L)])
        for _ in range(g.n(200, L, 1)):
            w = g.val(L)
            if g.rnd.random() < 0.3:
                w = (g.rnd.choice(M.SMALL_PRIMES) * g.rnd.getrandbits(max(1, 64 * L - 11))) % Rr
            g.call("has_small_factor", {"L": L, "w": hl(w, L)}, lambda: M.has_small_factor(w, L), lambda v: [str(int(v))])
        for w in M.SMALL_PRIMES[:8] + M.SMALL_PRIMES[-4:] + [1021 * 1021, 1031, 1031 * 1033]:
            g.call("has_small_factor", {"L": L, "w": hl(w, L)}, lambda w=w: M.has_small_factor(w, L), lambda v: [str(int(v))])
        if L >= 2:                                           # K3: the bound needs 64L >= 100
            t = 1 << (64 * L - 100)
            for _ in range(g.n(30)):
                p = g.rnd.getrandbits(64 * L - 1) | (1 << (64 * L - 2))
                for delta in (0, 1, t - 1, t, t + 1, 2 * t, g.rnd.getrandbits(64 * L - 2)):
                    for q in (p + delta, p - delta):
                        if 0 <= q < Rr:
                            g.call("primes_too_close", {"L": L, "p": hl(p, L), "q": hl(q, L)},
                                   lambda q=q: M.primes_too_close(p, q, L), lambda v: [str(int(v))])


def primality_and_keygen(g):
    rnd = g.rnd
    known = [0, 1, 2, 3, 4, 9, 561, 1021, 1023, 1024 * 1024 - 3, 1048573, 1048575, 1048576 + 7,
             41041, 825265, (1 << 61) - 1, (1 << 61) + 1]
    for L in (1, 2, 4, 8, 16):
        Rr = M.R(L)
        ws = [w for w in known if w < Rr]
        ws += [g.prime(64 * L) for _ in range(g.n(6, L, 2))]
        ws += [g.prime(max(21, 64 * L - 17)) for _ in range(g.n(4, L, 2))]            # short primes
        ws += [(g.prime(32 * L) * g.prime(32 * L)) for _ in range(g.n(6, L, 2))]       # semiprimes
        ws += [rnd.getrandbits(64 * L) | 1 for _ in range(g.n(20, L, 2))]
        ws += [w - 1 for w in ws[-3:]]                                                 # even
        for w in ws:
            for rounds in (1, 5):
                stream = rnd.randbytes(8 * L * rounds * 6)

                def fn(w=w, rounds=rounds, stream=stream):
                    rng = M.StreamRng(stream)
                    return M.is_probable_prime(w, rounds, rng, L), rng.pos
                g.call("is_probable_prime", {"L": L, "w": hl(w, L), "rounds": rounds, "stream": hb(stream)},
                       fn, lambda v: [str(int(v[0])), str(v[1])])
        # an RNG that cannot produce a base: all-zero and all-ones streams
        w = g.prime(64 * L)
        for fill in (b"\x00", b"\xff"):
            stream = fill * (8 * L * 128)
            g.call("is_probable_prime", {"L": L, "w": hl(w, L), "rounds": 1, "stream": hb(stream)},
                   lambda stream=stream: (M.is_probable_prime(w, 1, M.StreamRng(stream), L), 0), lambda v: [str(int(v[0])), str(v[1])])
    for L in (1, 2, 4, 8):
        for _ in range(g.n(6, L, 2)):
            stream = rnd.randbytes(8 * L * 6000)
            max_attempts = rnd.choice([1, 3, 5000])

            def fn(stream=stream, max_attempts=max_attempts):
                rng = M.StreamRng(stream)
                return M.random_prime(rng, 5, max_attempts, L), rng.pos
            g.call("random_prime", {"L": L, "rounds": 5, "max": max_attempts, "stream": hb(stream)},
                   fn, lambda v: [hl(v[0], L), str(v[1])])
        if L >= 2:
            p = g.prime(64 * L, top2=True)
            stream = rnd.randbytes(8 * L * 6000)

            def fn2(stream=stream, p=p):
                rng = M.StreamRng(stream)
                return M.random_prime(rng, 5, 5000, L, lambda c: not M.primes_too_close(p, c, L)), rng.pos
            g.call("random_prime", {"L": L, "rounds": 5, "max": 5000, "p": hl(p, L), "stream": hb(stream)},
                   fn2, lambda v: [hl(v[0], L), str(v[1])])
    # the whole of key generation at RSA-2048: same stream, same key
    def kg_fmt(v):
        pk, sk, pos = v
        return [hl(pk.n, 32), f"{pk.e:x}", f"{sk.e:x}", hl(sk.p, 16), hl(sk.q, 16), hl(sk.d_p, 16), hl(sk.d_q, 16), hl(sk.q_inv, 16), str(pos)]
    plans = [(rnd.randbytes(1 << 20), 256, 112, 5) for _ in range(max(1, int(g.scale * (2 if g.profile == "release" else 1))))]
    plans += [(rnd.randbytes(4096), 256, 112, 5),            # stream runs out
              (rnd.randbytes(4096), 0, 112, 5),              # RNG below the required strength
              (b"\x42" * (1 << 14), 256, 112, 5)]            # exhausted while every candidate is the same
    if g.profile == "release":
        plans.append((b"\x42" * (3 << 20), 256, 112, 5))    # a stuck RNG: step 4.7's candidate limit
    for stream, strength, required, rounds in plans:
        def fn3(stream=stream, strength=strength, required=required, rounds=rounds):
            rng = M.StreamRng(stream, strength)
            pk, sk = M.keygen_from_rng(rng, rounds, required, 16)
            return pk, sk, rng.pos
        g.call("keygen", {"HALF": 16, "rounds": rounds, "strength": strength, "required": required, "stream": hb(stream)}, fn3, kg_fmt)


def leakage(g):
    """M2': the subtract decisions of the variable-time doubling chain (`pow2_mod_vartime`,
    which `for_public_modulus` runs and, since 04305e0, nothing runs over a secret) are the
    binary digits of floor(2^k / n). The runner reads the decisions off the Rust function's own
    outputs; the model computes the quotient. For a prime of exactly 64L bits, the 128L
    decisions of the R^2 chain give p back as floor(2^(128L) / Q), which is checked here before
    the case is emitted, so a 'match' means: the Rust decisions determine the prime."""
    for L in (1, 2, 4, 8, 16, 24, 32, 64):
        h = 64 * L
        primes = [g.prime(h, top2=True) for _ in range(g.n(3, L, 3))] + [g.prime(h) for _ in range(g.n(2, L, 3))]
        for p in primes:
            dec = M.pow2_mod_decisions(2 * h, p)
            Q = int("".join(map(str, dec)), 2)
            assert (1 << (2 * h)) // Q == p and sum(dec[:h - 1]) == 0 and dec[h - 1] == 1
            # about h/2 decisions past the first h fix the top half of p (Coppersmith's range)
            t = h // 2 + 8
            Qt = int("".join(map(str, dec[:h + t])), 2)
            assert ((p ^ ((1 << (h + t)) // Qt)) >> (h - t + 8)) == 0
            for bits in (h, 2 * h):
                g.call("pow2_trace", {"L": L, "bits": bits, "n": hl(p, L)},
                       lambda bits=bits: (M.pow2_mod_decisions(bits, p), M.pow2_mod(bits, p, L)),
                       lambda v: ["".join(map(str, v[0])), hl(v[1], L)])
        for _ in range(g.n(3, L, 3)):                       # any odd modulus > 1, prime or not
            n = g.odd_mod(L)
            g.call("pow2_trace", {"L": L, "bits": 2 * h, "n": hl(n, L)},
                   lambda: (M.pow2_mod_decisions(2 * h, n), M.pow2_mod(2 * h, n, L)),
                   lambda v: ["".join(map(str, v[0])), hl(v[1], L)])


# ------------------------------------------------------------------ WP14.3: the new families
def _err_token(error_type, message):
    """A constructor's refusal as diff_runner prints it: `ERR:` and the error's Debug form."""
    return f'ERR:{error_type}("{message}")'.replace(" ", "_")


def _verdict_token(fn, error_type):
    try:
        fn()
        return "OK"
    except M.ModelError as err:
        return _err_token(error_type, err.detail)


def constructors(g):
    """I1 and I2. Every public path to a key -- the components, the signature key, its decoder,
    the key-establishment key, its decoder -- on one tuple, against the model's ordered checks;
    the accept/refuse verdict is asserted equal to I1's predicate as the case is written. On
    acceptance the key's own encoding is compared byte for byte, and the runner reports
    whether decoding it gives the key back. No primality is needed: the constructors test
    none, so the tuples are random integers of the shapes that matter."""
    rnd = g.rnd
    E_ALL = [0, 1, 2, 3, 4, 65535, 65536, 65537, (1 << 32) + 1, M.BETA - 1]

    def public(bits, n, e):
        k_len = bits // 8
        accept = M.i1_public(n, e, bits)
        comp = _verdict_token(lambda: M.key_public_new(n, e, k_len), "DecodingError")
        assert (comp == "OK") == accept, "the model's constructor and I1 disagree"
        own = M.PublicComponents(n, e, k_len).encode().hex() if accept else "-"
        exp = [comp, comp,
               _verdict_token(lambda: M.key_public_new(n, e, k_len), "KeyDecodingError"),
               _verdict_token(lambda: M.kem_public_new(n, e, k_len), "DecodingError"),
               _verdict_token(lambda: M.kem_public_new(n, e, k_len), "KeyDecodingError"),
               own, "1" if accept else "-"]
        g.add("key_public", {"BITS": bits, "n": hl(n, bits // 64), "e": f"{e:x}"}, ("OK", exp))

    def private(bits, p, q, dp, dq, qi, e):
        k_len, H = bits // 8, bits // 128
        half = M.R(H)
        if not all(0 <= v < half for v in (p, q, dp, dq, qi)):
            return
        accept = M.i1_private(p, q, dp, dq, qi, e, bits)
        comp = _verdict_token(lambda: M.key_private_new(p, q, dp, dq, qi, e, k_len), "DecodingError")
        assert (comp == "OK") == accept, "the model's constructor and I1 disagree"
        if accept:
            assert p.bit_length() == q.bit_length() == bits // 2      # I1's consequence (N12)
            n_tok, own = hl(p * q, bits // 64), M.PrivateComponents(p, q, dp, dq, qi, k_len, e).encode().hex()
        else:
            n_tok, own = "-", "-"
        exp = [comp, comp,
               _verdict_token(lambda: M.key_private_new(p, q, dp, dq, qi, e, k_len), "KeyDecodingError"),
               _verdict_token(lambda: M.kem_private_new(p, q, dp, dq, qi, e, k_len), "DecodingError"),
               _verdict_token(lambda: M.kem_private_new(p, q, dp, dq, qi, e, k_len), "KeyDecodingError"),
               n_tok, own, "1" if accept else "-"]
        g.add("key_private", {"BITS": bits, "p": hl(p, H), "q": hl(q, H), "dp": hl(dp, H), "dq": hl(dq, H),
                              "qinv": hl(qi, H), "e": f"{e:x}"}, ("OK", exp))

    for bits in (1024, 1536, 2048, 3072, 4096, 8192):
        top = 1 << (bits - 1)
        edges = [1, 3, top + 1, top - 1, (1 << bits) - 1, top, top + 2, (1 << bits) - 2,
                 (1 << 960) + 0xFFFFFFFFFFFFFFFB,                 # the first pass's 961-bit modulus
                 (1 << (bits - 5)) + 0xD]                         # four bits short (2044 bits at RSA-2048)
        if bits == 2048:                                          # the 2047-bit product of two 1024-bit primes
            while True:
                a, b = g.prime(1024), g.prime(1024)
                if (a * b).bit_length() == 2047:
                    break
            edges.append(a * b)
        for n in edges:
            for e in E_ALL:
                public(bits, n, e)
        rand = [rnd.getrandbits(bits) | 1 | top for _ in range(g.n(8))]
        rand += [rnd.getrandbits(bits - rnd.randrange(1, 70)) | 1 for _ in range(g.n(4))]
        rand += [rnd.getrandbits(bits) & ~1 for _ in range(2)]
        for n in rand:
            for e in rnd.sample(E_ALL, 3) + [rnd.getrandbits(64), rnd.getrandbits(64) | 1]:
                public(bits, n, e)

    for bits in (2048, 3072, 4096, 8192):
        h = bits // 2
        Rh, floor = 1 << h, 1 << (bits - 1)

        def base():
            """A tuple the constructor admits: odd p != q with their top two bits set, the
            other three components anywhere below their prime."""
            while True:
                p, q = rnd.getrandbits(h) | 1 | (3 << (h - 2)), rnd.getrandbits(h) | 1 | (3 << (h - 2))
                if p != q:
                    return p, q, rnd.randrange(p), rnd.randrange(q), rnd.randrange(p)

        p, q, dp, dq, qi = base()
        for e in E_ALL:                                           # the exponent rule, on the private half
            private(bits, p, q, dp, dq, qi, e)
        for _ in range(g.n(3)):
            p, q, dp, dq, qi = base()
            e = 65537
            private(bits, p, q, dp, dq, qi, e)
            private(bits, p ^ 1, q, dp, dq, qi, e)                # even p, even q
            private(bits, p, q ^ 1, dp, dq, qi, e)
            private(bits, p, p, dp, min(dq, p - 1), qi, e)        # p == q
            for d in (0, p - 1, p, p + 1):                        # dP at its bound
                private(bits, p, q, d, dq, qi, e)
            for d in (0, q - 1, q, q + 1):
                private(bits, p, q, dp, d, qi, e)
            for d in (0, p - 1, p, p + 1):
                private(bits, p, q, dp, dq, d, e)
            # the modulus's length, at its boundary: the least odd q with p*q >= 2^(bits-1), and
            # the odd number below it
            q_min = -(-floor // p) | 1
            if q_min != p and q_min - 2 != p:
                private(bits, p, q_min, dp, 0, qi, e)
                private(bits, p, q_min - 2, dp, 0, qi, e)
        # shapes named in the plan and the first pass
        private(bits, 1, 3, 0, 1, 0, 65537)                       # p = 1 (map flag 5, N4)
        private(bits, 3, 5, 1, 1, 2, 65537)                       # n = 15 in a full-size key type
        lo = (1 << (h - 1)) + 1
        private(bits, lo, lo + 2, 0, 0, 0, 65537)                 # both primes h bits, n one bit short
        private(bits, Rh - 1, lo, 0, 0, 0, 65537)                 # the largest p with the least h-bit q: full length
        private(bits, Rh - 1, (1 << (h - 1)) - 1, 0, 0, 0, 65537)  # unequal lengths: h and h - 1 bits (N12)
        private(bits, Rh - 1, (1 << (h - 24)) + 1, 0, 0, 0, 65537)  # h and h - 23 bits
        private(bits, Rh - 1, (1 << (h - 64)) - 1, 0, 0, 0, 65537)  # a prime with its top limb zero
        private(bits, (1 << (h - 2)) + 1, (1 << (h - 2)) + 3, 0, 0, 0, 65537)   # four bits short
        for _ in range(g.n(6)):                                   # anything at all
            vals = [rnd.getrandbits(rnd.choice([h, h, h - 1, 64, h - 64])) for _ in range(5)]
            private(bits, vals[0] | rnd.randrange(2), vals[1] | rnd.randrange(2), vals[2], vals[3], vals[4],
                    rnd.choice(E_ALL))


def public_exponent(g):
    """M11 at every width: `mod_pow_public_exponent` and `public_exp` over e in {0, 1, 2, 3,
    65537, 2^32 + 1, 2^56 - 1, 2^64 - 1} and random 64-bit exponents, with bases 0, 1, n - 1,
    below n, and at or above n (the function's contract is a base of L limbs)."""
    rnd = g.rnd
    ES = [0, 1, 2, 3, 65537, (1 << 32) + 1, (1 << 56) - 1, M.BETA - 1]
    for L in WIDTHS:
        Rr = M.R(L)
        for _ in range(g.n(20, L, 2)):
            n = g.odd_mod(L)
            ctx = M.MontgomeryContext.for_public_modulus(n, L)
            for e in ES + [rnd.getrandbits(64), rnd.getrandbits(17) | 1]:
                base = rnd.choice([0, 1, n - 1, rnd.randrange(n), rnd.randrange(n), min(n, Rr - 1),
                                   min(n + 1, Rr - 1), Rr - 1, rnd.randrange(Rr)])
                g.call("mod_pow_public_exponent", {"L": L, "base": hl(base, L), "e": f"{e:x}", "n": hl(n, L)},
                       lambda e=e, base=base: M.mod_pow_public_exponent(base, e, ctx), lambda v: [hl(v, L)])
                g.call("public_exp", {"L": L, "n": hl(n, L), "e": f"{e:x}", "x": hl(base, L)},
                       lambda e=e, base=base: M.public_exp(n, e, base, L), lambda v: [hl(v, L)])


def checked_crt(g):
    """C7 to C9 on `crt_exp_checked`, at every prime width. The model computes each verdict;
    no case is assumed to fail.
      sound keys      x in {0, 1, 2, n-1, p, q, multiples of p and of q} and random x: C8
      x >= n          the answer is (false, 0): C7
      one bit flipped in p, q, dP, dQ or qInv, where the constructor still admits the key: C9
      a foreign e     on the nine residues 0, 1, -1 modulo each prime, which pass whatever the
                      odd exponent is, and on random x: C9"""
    rnd = g.rnd
    e = 65537
    for HALF in HALVES:
        L, h = 2 * HALF, 64 * HALF

        def emit(p, q, dp, dq, qi, n, ee, x):
            args = {"HALF": HALF, "p": hl(p, HALF), "q": hl(q, HALF), "dp": hl(dp, HALF), "dq": hl(dq, HALF),
                    "qinv": hl(qi, HALF), "n": hl(n, L), "e": f"{ee:x}", "x": hl(x, L)}
            g.call("crt_exp_checked", args,
                   lambda: M.crt_exp_checked(p, q, dp, dq, qi, n, ee, x, L, HALF),
                   lambda v: [str(int(v[0])), hl(v[1], L)])

        p, q, dp, dq, qi, n = g.key(HALF)
        xs = [0, 1, 2, n - 1, p, q, (5 * p) % n, (7 * q) % n, n - p, n - q]
        for x in xs + [rnd.randrange(n) for _ in range(g.n(6, HALF, 3))]:
            emit(p, q, dp, dq, qi, n, e, x)
        for x in (n, n + 1, M.R(L) - 1):
            emit(p, q, dp, dq, qi, n, e, x)
        for name in ("p", "q", "dp", "dq", "qinv"):
            for _ in range(max(1, g.n(2, HALF, 3))):
                for _attempt in range(400):
                    c = {"p": p, "q": q, "dp": dp, "dq": dq, "qinv": qi}
                    c[name] ^= 1 << rnd.randrange(h)
                    if M.i1_private(c["p"], c["q"], c["dp"], c["dq"], c["qinv"], e, 2 * h):
                        break
                else:
                    continue
                n2 = c["p"] * c["q"]
                for x in (0, 1, n2 - 1, rnd.randrange(n2), rnd.randrange(n2)):
                    emit(c["p"], c["q"], c["dp"], c["dq"], c["qinv"], n2, e, x)
        for e2 in (3, 65539, (1 << 32) + 1, M.BETA - 1):
            nine = [(b + q * (((a - b) * qi) % p)) % n for a in (0, 1, p - 1) for b in (0, 1, q - 1)]
            assert all(x % p in (0, 1, p - 1) and x % q in (0, 1, q - 1) for x in nine) and len(set(nine)) == 9
            for x in nine + [rnd.randrange(n) for _ in range(2)]:
                emit(p, q, dp, dq, qi, n, e2, x)


def from_hash_lengths(g):
    """E11. The four `*_from_hash` entry points at RSA-2048 (PKCS #1 v1.5, salted PSS, unsalted
    PSS) and `emsa_encode` / `emsa_verify` through the public algorithm traits, with hashes and
    salts of {0, 1, hLen - 1, hLen, hLen + 1, 64, 65, 130, 4096} bytes: an error the model
    names, never a panic; with the right lengths, the model's signature byte for byte. The
    RNG path reports its calls: none before the hash's length is checked. RFC 8017 section
    9.1.1 step 3 at its boundary is RSA-1024 with SHA-512 and salts of 62 and 63 bytes."""
    rnd = g.rnd
    sha256, sha512 = M.HASHES["SHA-256"], M.HASHES["SHA-512"]
    mgf, mgf512 = M.Mgf("mgf1", sha256), M.Mgf("mgf1", sha512)
    p, q, dp, dq, qi, n = g.key(16)
    e = 65537
    sk, pk = M.key_private_new(p, q, dp, dq, qi, e, 256), M.key_public_new(n, e, 256)
    K = {"p": hl(p, 16), "q": hl(q, 16), "dp": hl(dp, 16), "dq": hl(dq, 16), "qinv": hl(qi, 16), "e": f"{e:x}"}
    LENS = (0, 1, 31, 32, 33, 64, 65, 130, 4096)
    sig = lambda v: [v.hex()]
    bit = lambda v: [str(int(v))]
    valid = lambda v: ["VALID"]

    def rng_case(h, stream):
        args = {**K, "scheme": "pss", "entry": "sign_rng", "hash": hb(h), "stream": hb(stream)}
        rng = M.StreamRng(stream)
        try:
            s = M.crate_sign_from_hash_pss_rng(sk, sha256, mgf, h, 32, rng)
            g.add("from_hash", args, ("OK", [s.hex(), f"calls={rng.calls}", f"consumed={rng.pos}"]))
        except M.ModelError as err:
            kind = ERR_KINDS.get((err.kind, err.detail), err.kind)
            g.add("from_hash", args, ("ERR", kind, [f"calls={rng.calls}", f"consumed={rng.pos}"]))

    good_h = rnd.randbytes(32)
    good = {"v15": M.crate_sign_from_hash_v15(sk, sha256, good_h),
            "pss": M.crate_sign_from_hash_pss(sk, sha256, mgf, good_h, rnd.randbytes(32), 32),
            "pssns": M.crate_sign_from_hash_pss(sk, sha256, mgf, good_h, b"", 0)}
    verify_em = {"v15": lambda mh, em: M.crate_emsa_v15_verify(sha256, mh, em),
                 "pss": lambda mh, em: M.crate_emsa_pss_verify(sha256, mgf, mh, em, 32),
                 "pssns": lambda mh, em: M.crate_emsa_pss_verify(sha256, mgf, mh, em, 0)}
    for hlen in LENS:
        for h in ([good_h] if hlen == 32 else []) + [rnd.randbytes(hlen)]:
            F = {**K, "hash": hb(h)}
            g.call("from_hash", {**F, "scheme": "v15", "entry": "sign_det"},
                   lambda h=h: M.crate_sign_from_hash_v15(sk, sha256, h), sig)
            g.call("from_hash", {**F, "scheme": "pssns", "entry": "sign_det"},
                   lambda h=h: M.crate_sign_from_hash_pss(sk, sha256, mgf, h, b"", 0), sig)
            for slen in LENS:
                salt = rnd.randbytes(slen)
                g.call("from_hash", {**F, "scheme": "pss", "entry": "sign_salt", "salt": hb(salt)},
                       lambda h=h, salt=salt: M.crate_sign_from_hash_pss(sk, sha256, mgf, h, salt, 32), sig)
                g.call("emsa", {"scheme": "pss", "entry": "encode", "hash": hb(h), "salt": hb(salt)},
                       lambda h=h, salt=salt: M.crate_emsa_pss_encode(sha256, mgf, h, salt, 32, 256), sig)
            rng_case(h, rnd.randbytes(64))
            rng_case(h, rnd.randbytes(31))                        # a stream one byte short of a salt
            for scheme in ("v15", "pss", "pssns"):
                g.call("from_hash", {**F, "scheme": scheme, "entry": "verify", "sig": good[scheme].hex()},
                       lambda h=h, scheme=scheme: M.crate_verify_from_hash(pk, sha256, h, good[scheme], verify_em[scheme]), valid)
                em_good = M.i2osp(pow(M.os2ip(good[scheme]), e, n), 256)
                g.call("emsa", {"scheme": scheme, "entry": "verify", "hash": hb(h), "em": em_good.hex()},
                       lambda h=h, scheme=scheme, em_good=em_good: verify_em[scheme](h, em_good), bit)
            g.call("emsa", {"scheme": "v15", "entry": "encode", "hash": hb(h)},
                   lambda h=h: M.crate_emsa_v15_encode(sha256, h, 256), sig)
            g.call("emsa", {"scheme": "pssns", "entry": "encode", "hash": hb(h)},
                   lambda h=h: M.crate_emsa_pss_encode(sha256, mgf, h, b"", 0, 256), sig)
    # verification: a representative at or above n, and a signature that does not verify
    for scheme in ("v15", "pss", "pssns"):
        F = {**K, "scheme": scheme, "entry": "verify", "hash": hb(good_h)}
        for bad in (M.i2osp(n, 256), M.i2osp(n + 1, 256), b"\xff" * 256,
                    bytes([good[scheme][0] ^ 1]) + good[scheme][1:], good[scheme][:-1] + bytes([good[scheme][-1] ^ 1]),
                    bytes(256)):
            g.call("from_hash", {**F, "sig": bad.hex()},
                   lambda bad=bad, scheme=scheme: M.crate_verify_from_hash(pk, sha256, good_h, bad, verify_em[scheme]), valid)
    # RFC 8017 section 9.1.1 step 3 at its boundary: emLen = 128, hLen = 64; sLen 62 fits, 63 does not.
    for s_len in (62, 63):
        scheme = f"pss1024_{s_len}"
        for hlen in (0, 63, 64, 65):
            for slen in (0, 61, 62, 63, 64):
                h, salt = rnd.randbytes(hlen), rnd.randbytes(slen)
                g.call("emsa", {"scheme": scheme, "entry": "encode", "hash": hb(h), "salt": hb(salt)},
                       lambda h=h, salt=salt, s_len=s_len: M.crate_emsa_pss_encode(sha512, mgf512, h, salt, s_len, 128), sig)
        h64 = rnd.randbytes(64)
        em62 = M.crate_emsa_pss_encode(sha512, mgf512, h64, rnd.randbytes(62), 62, 128)
        for h in (h64, h64[:63], rnd.randbytes(64)):
            g.call("emsa", {"scheme": scheme, "entry": "verify", "hash": hb(h), "em": em62.hex()},
                   lambda h=h, s_len=s_len: M.crate_emsa_pss_verify(sha512, mgf512, h, em62, s_len), bit)


def rng_draws(g):
    """K16. `fill_bytes` against an RNG that fills the buffer and reports a count of its own
    choosing, or its own error: Ok exactly when the count is the buffer's length; otherwise
    an error, with the buffer zero. One call of the RNG either way."""
    for length in (0, 1, 8, 32, 64, 1000):
        for claim in ("err", 0, 1, length - 1, length, length + 1, 4096):
            if claim != "err" and claim < 0:
                continue
            args = {"len": length, "claim": claim}
            if M.fill_bytes(length, None if claim == "err" else claim):
                g.add("fill_bytes", args, ("OK", ["FILLED", "calls=1", "buf=zero" if length == 0 else "buf=filled"]))
            else:
                g.add("fill_bytes", args, ("ERR", "RNG_OWN" if claim == "err" else "RNG_SHORT", ["calls=1", "buf=zero"]))


FAMILIES = {"substrate": substrate, "modexp": modexp, "rsa_core": rsa_core, "leakage": leakage,
            "keygen_helpers": keygen_helpers, "primality_and_keygen": primality_and_keygen,
            "constructors": constructors, "public_exponent": public_exponent, "checked_crt": checked_crt,
            "from_hash_lengths": from_hash_lengths, "rng_draws": rng_draws}


def rust_err_kind(tag):
    if "fewer_bytes" in tag and not tag.startswith("RNGError("):
        return "RNG_SHORT"                      # fill_bytes: a count short of, or past, the buffer
    if "its_own_error" in tag and not tag.startswith("RNGError("):
        return "RNG_OWN"                        # fill_bytes: the RNG's own error, passed on
    if tag.startswith("LengthError("):
        return "LENGTH_HASH" if "message_hash" in tag else ("LENGTH_SALT" if "salt" in tag else "LENGTH_OTHER")
    if tag.startswith("EncodingError("):
        return "ENCODING"
    if tag == "SignatureVerificationFailed":
        return "VERIFICATION_FAILED"
    if tag == "ComputationFault":
        return "COMPUTATION_FAULT"
    if tag.startswith("RNGError(SecurityStrengthInsufficientForAlgorithm"):
        return "RNG_STRENGTH"
    if tag.startswith("RNGError("):
        return "RNG_ERROR"
    if tag.startswith("GenericError("):
        return "GENERIC"
    if tag.startswith("DecodingError("):
        return "DECODING"
    return tag


def judge(op, exp, got):
    """The verdict on one result line `got` (its tokens after the case id) under the
    expectation `exp`."""
    if got is None:
        return "NO_RESULT"
    if exp[0] == "OBSERVE":
        return "observation"
    if exp[0] == "EXPECTED_PANIC":
        return "expected" if got[0] == "PANIC" and exp[1] in got[1] else "MISMATCH"
    if got[0] == "PANIC":
        return "PANIC"
    if got[0] == "HARNESS":
        return "HARNESS"
    if exp[0] == "OK":
        return "match" if got[0] == "OK" and got[1:] == exp[1] else "MISMATCH"
    # ERR, and what follows the tag where the expectation names it
    verdict = "match" if got[0] == "ERR" and rust_err_kind(got[1]) == exp[1] else "MISMATCH"
    if verdict == "match" and len(exp) > 2 and got[2:] != exp[2]:
        verdict = "MISMATCH"
    # random_prime reports its candidate buffer: zeroed when the candidate limit is hit
    if verdict == "match" and op == "random_prime" and exp[1] == "GENERIC" and set(got[2]) != {"0"}:
        verdict = "MISMATCH"
    return verdict


def judge_control(cases, results):
    """A judge that cannot fail proves nothing. For a sample of matching cases, each token the
    judge is meant to compare is altered in turn and the altered line judged again: every one
    must stop being a match. Returns (altered lines tried, those still accepted)."""
    def alter(tok):
        if tok in ("OK", "ERR"):
            return "ERR" if tok == "OK" else "OK"
        last = tok[-1]
        return tok[:-1] + ("1" if last != "1" else "2")
    tried, blind, seen = 0, [], {}
    for cid, op, _args, exp in cases:
        got = results.get(cid)
        if exp[0] not in ("OK", "ERR") or judge(op, exp, got) != "match":
            continue
        seen[op] = seen.get(op, 0) + 1
        if seen[op] > 3 and cid % 37:
            continue                            # the first three of each operation, then 1 in 37
        compared = range(len(got)) if exp[0] == "OK" or len(exp) > 2 else range(2)
        for i in compared:
            bad = list(got)
            bad[i] = "Zzz" if (exp[0] == "ERR" and i == 1) else alter(bad[i])
            tried += 1
            if judge(op, exp, bad) == "match":
                blind.append((cid, op, i, got[i][:40]))
    return tried, blind


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runner", required=True)
    ap.add_argument("--profile", choices=("debug", "release"), required=True)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--seed", type=int, default=20261122)
    ap.add_argument("--families", default=",".join(FAMILIES))
    ap.add_argument("--keep")
    ap.add_argument("--max-width", type=int, default=128,
                    help="largest limb count L to generate cases for (a quick run: 16)")
    a = ap.parse_args()
    global WIDTHS, HALVES, REDUCE_PAIRS
    WIDTHS = tuple(w for w in WIDTHS if w <= a.max_width)
    HALVES = tuple(h for h in HALVES if 2 * h <= a.max_width)
    REDUCE_PAIRS = tuple(pr for pr in REDUCE_PAIRS if max(pr) <= a.max_width)

    g = Gen(a.seed, a.scale, a.profile)
    t0 = time.time()
    for name in a.families.split(","):
        FAMILIES[name](g)
    gen_s = time.time() - t0
    text = "".join(f"{cid} {op} " + " ".join(f"{k}={v}" for k, v in args.items()) + "\n" for cid, op, args, _ in g.cases)
    if a.keep:
        os.makedirs(a.keep, exist_ok=True)
        open(os.path.join(a.keep, f"cases-{a.profile}.txt"), "w").write(text)
    t0 = time.time()
    proc = subprocess.run([a.runner], input=text.encode(), capture_output=True)
    run_s = time.time() - t0
    out = proc.stdout.decode()
    if a.keep:
        open(os.path.join(a.keep, f"results-{a.profile}.txt"), "w").write(out)
    results = {}
    for line in out.splitlines():
        parts = line.split()
        results[int(parts[0])] = parts[1:]

    tally = {}
    problems, observations = [], []
    for cid, op, args, exp in g.cases:
        got = results.get(cid)
        short = {k: (v if len(str(v)) <= 40 else str(v)[:18] + f"..({len(str(v))})") for k, v in args.items()}
        verdict = judge(op, exp, got)
        if verdict == "observation":
            observations.append((op, short, exp[1], " ".join(got)[:160]))
        tally.setdefault(op, {}).setdefault(verdict, 0)
        tally[op][verdict] += 1
        if verdict in ("MISMATCH", "PANIC", "NO_RESULT", "HARNESS"):
            problems.append((cid, op, short, exp, got))

    print(f"differential run: profile={a.profile} seed={a.seed} scale={a.scale} families={a.families} "
          f"max-width={a.max_width} cases={len(g.cases)} "
          f"(generated in {gen_s:.1f}s, run in {run_s:.1f}s, runner exit {proc.returncode})")
    cols = ("match", "expected", "observation", "MISMATCH", "PANIC", "NO_RESULT", "HARNESS")
    print(f"{'operation':22s}" + "".join(f"{c:>12s}" for c in cols))
    total = dict.fromkeys(cols, 0)
    for op in sorted(tally):
        print(f"{op:22s}" + "".join(f"{tally[op].get(c, 0):12d}" for c in cols))
        for c in cols:
            total[c] += tally[op].get(c, 0)
    print(f"{'TOTAL':22s}" + "".join(f"{total[c]:12d}" for c in cols))
    if observations:
        print("\nobservations (outside the model's contract; listed, not judged):")
        seen = set()
        for op, short, why, got in observations:
            key = (op, why, got.split()[0])
            if key in seen:
                continue
            seen.add(key)
            print(f"  {op} {short}\n      contract: {why}\n      rust: {got}")
    for cid, op, short, exp, got in problems[:40]:
        print(f"\nPROBLEM case {cid}: {op} {short}\n   model: {exp}\n   rust:  {got}")
    # what the model predicted, by kind: a run in which nothing is ever refused, or nothing
    # ever accepted, would be a weak one
    kinds = {}
    for _cid, op, _args, exp in g.cases:
        if op in ("crt_exp_checked", "key_public", "key_private", "from_hash", "emsa", "fill_bytes"):
            if exp[0] == "OK":
                k = {"crt_exp_checked": lambda v: "released" if v[0] == "1" else "refused, out = 0",
                     "key_public": lambda v: "accepted" if v[0] == "OK" else "refused",
                     "key_private": lambda v: "accepted" if v[0] == "OK" else "refused"}.get(op, lambda v: "value")(exp[1])
            else:
                k = "observation" if exp[0] == "OBSERVE" else f"error {exp[1]}"
            kinds.setdefault(op, {}).setdefault(k, 0)
            kinds[op][k] += 1
    if kinds:
        print("\nwhat the model predicted for the response's operations:")
        for op in sorted(kinds):
            print(f"  {op:18s} " + "; ".join(f"{k}: {v}" for k, v in sorted(kinds[op].items())))
    tried, blind = judge_control(g.cases, results)
    print(f"\njudge control: {tried} altered result tokens re-judged, {len(blind)} still accepted")
    for item in blind[:10]:
        print(f"  BLIND: case {item[0]} {item[1]} token {item[2]} ({item[3]})")
    bad = sum(total[c] for c in ("MISMATCH", "PANIC", "NO_RESULT", "HARNESS")) or proc.returncode != 0 or blind or tried == 0
    print("\nDIFFERENTIAL RUN FAILED" if bad else "\nDIFFERENTIAL RUN PASSED")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
