#!/usr/bin/env python3
"""Reference model for the bc-rust RSA audit: one function per Rust function.

Target: bcgit/bc-rust, branch feature/rsa-sig, 30cbbab (crypto/rsa, and the limb kernels of
crypto/ec it executes). Written against b7e46cb (WP0) and ported in WP14.3 to the code as it is
after the upstream response. Standard library only. `selftest.py` must pass before this file
is used to judge the Rust code.

Two layers since the port
-------------------------
The functions and classes of sections 1 to 9 are the specification layer, unchanged in what
they compute: they take keys of any length and treat a call the specification does not define
as a ContractError. Section 10 is the crate layer: what the Rust API is specified to answer
where the specification is silent -- the constructors' acceptance rules (plan obligation I1),
the length rules of the `*_from_hash` entry points (E11), the check of every private-key
result (C7), `fill_bytes` (K16). There a wrong length is an error the model predicts, not a
call it declines to judge.

What a function here is
-----------------------
Each function has the name and the argument order of the Rust function it stands for, and
computes the *mathematical* value that function is specified to return, with Python integers.
It does not copy the Rust algorithm: `redc` is the definition of Montgomery reduction, not the
SOS loop; `mod_pow` is `pow`; `inverse_of_e_mod` is the modular inverse. A limb array `[u64; L]`
is an integer in [0, 2^(64 L)) together with its width L.

Preconditions are the ones of the audit plan's proof obligations (section 4), not the narrower
ones some Rust doc comments state. A call outside them raises ContractError, so a differential
run can tell "the Rust result is wrong" from "the model has no opinion".

Key generation is the one exception to "specification, not algorithm": `keygen_from_rng` and
`is_probable_prime` follow the Rust code's order of draws from the RNG, so that both sides fed
the same byte stream must produce the same key. The arithmetic inside is still Python's.

Where each specification was read (2026-11-19)
----------------------------------------------
RFC 8017, RFC 8702, RFC 5869: read from the text files (Ubuntu doc-rfc 20230121-1; SHA-256 in
the WP0 report). Step numbers in comments below are from those files.
FIPS 186-5 (A.1.1, A.1.3, B.3.1) and SP 800-56B Rev. 2 (7.1, 7.2.1): known in this session only
through an extraction of the NIST PDFs, not by reading the pages. Every comment that rests on
them is marked [extraction]; WP6 and WP8 re-read the clauses before a finding cites them.
"""
import hashlib
import hmac as _hmac

BETA = 1 << 64


class ContractError(Exception):
    """The call is outside the function's stated precondition."""


class ModelError(Exception):
    """An error the modelled operation reports. `kind` is a stable tag for comparison."""

    def __init__(self, kind, detail=""):
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind
        self.detail = detail


def R(L):
    return 1 << (64 * L)


def _need(cond, what):
    if not cond:
        raise ContractError(what)


def to_limbs(x, L):
    _need(0 <= x < R(L), "value does not fit the width")
    return [(x >> (64 * i)) & (BETA - 1) for i in range(L)]


def from_limbs(limbs):
    return sum(v << (64 * i) for i, v in enumerate(limbs))


# =====================================================================================
# 1. Substrate: bouncycastle_ec::nat, bouncycastle_ec::montgomery          (S1 - S6)
# =====================================================================================

def nat_add(a, b, L):
    """S1. (s, c) with c in {0,1} and s + c*R = a + b."""
    _need(0 <= a < R(L) and 0 <= b < R(L), "nat_add operands")
    t = a + b
    return t % R(L), t >> (64 * L)


def nat_sub(a, b, L):
    """S2. (d, borrow) with borrow in {0,1} and d - borrow*R = a - b; borrow = 1 iff a < b."""
    _need(0 <= a < R(L) and 0 <= b < R(L), "nat_sub operands")
    t = a - b
    return t % R(L), 1 if t < 0 else 0


nat_add_assign = nat_add     # in-place forms: same function of the values
nat_sub_assign = nat_sub


def nat_is_zero(a, L):
    """S3."""
    _need(0 <= a < R(L), "nat_is_zero operand")
    return a == 0


def widening_mul(a, b, L):
    """S4. The 2L-limb product."""
    _need(0 <= a < R(L) and 0 <= b < R(L), "widening_mul operands")
    return a * b


def widening_square(a, L):
    """S5."""
    _need(0 <= a < R(L), "widening_square operand")
    return a * a


def redc(t, modulus, n_prime, L):
    """S6. Montgomery reduction by definition.

    For odd n with n*n' = -1 (mod 2^64) and T < n*R: m is the unique element of [0, R) with
    T + m*n = 0 (mod R), u = (T + m*n)/R, and the result is (u mod R, u div R). Then
    u = T*R^-1 (mod n), u < 2n, and the second component is 0 or 1.
    """
    n, Rr = modulus, R(L)
    _need(n & 1 == 1 and 0 < n < Rr, "redc: modulus odd, nonzero, L limbs")
    _need((n * n_prime) % BETA == BETA - 1 and 0 <= n_prime < BETA, "redc: n*n' = -1 mod 2^64")
    _need(0 <= t < n * Rr, "redc: T < n*R")
    m = (t * (-pow(n, -1, Rr))) % Rr
    u = (t + m * n) // Rr
    assert (t + m * n) % Rr == 0 and u < 2 * n
    return u % Rr, u // Rr


# =====================================================================================
# 2. crypto/rsa/src/modexp.rs                                             (M1 - M9)
# =====================================================================================

def mont_n_prime(n0):
    """M1. -n0^-1 mod 2^64 for odd n0."""
    _need(n0 & 1 == 1 and 0 < n0 < BETA, "mont_n_prime: odd limb")
    return (-pow(n0, -1, BETA)) % BETA


def double_mod_n(a, n, L):
    """M2. 2a mod n for a < n. (n = 1 is outside the contract: see the plan's M2.)
    The Rust function is `double_mod_n_vartime` since 04305e0."""
    _need(1 < n < R(L) and 0 <= a < n, "double_mod_n: n > 1, a < n")
    return (2 * a) % n


def pow2_mod(bits, n, L):
    """M2, M2c. 2^bits mod n for n > 1: one value for both Rust forms, `pow2_mod_vartime`
    (branching doublings, public moduli) and `pow2_mod_ct` (masked doublings, secret moduli).
    Neither proof uses the oddness of n; the Rust docs ask for it because their callers do."""
    _need(1 < n < R(L) and bits >= 0, "pow2_mod: n > 1")
    return pow(2, bits, n)


double_mod_n_vartime = double_mod_n
pow2_mod_vartime = pow2_mod
pow2_mod_ct = pow2_mod


def pow2_mod_decisions(bits, n):
    """M2'. The subtract decisions of the doubling chain from 1: the binary digits of
    floor(2^bits / n), most significant first, as a list of 0/1 of length `bits`."""
    _need(n > 1 and bits >= 0, "pow2_mod_decisions: n > 1")
    q = (1 << bits) // n
    return [(q >> (bits - 1 - i)) & 1 for i in range(bits)]


class MontgomeryContext:
    """MontgomeryContext<L>: {modulus, n_prime, r_mod_n, r2_mod_n}."""

    def __init__(self, modulus, L):
        self.modulus, self.L = modulus, L
        self.n_prime = mont_n_prime(modulus % BETA)
        self.r_mod_n = R(L) % modulus
        self.r2_mod_n = (R(L) * R(L)) % modulus

    @staticmethod
    def for_public_modulus(modulus, L):
        """None if the modulus is even or zero (the Rust `None`). modulus = 1 is accepted by
        the Rust constructor but is outside M2; the model refuses to describe it."""
        _need(0 <= modulus < R(L), "for_public_modulus: modulus fits L limbs")
        if modulus & 1 == 0:          # covers zero
            return None
        _need(modulus > 1, "for_public_modulus: modulus = 1 is outside the contract (M2)")
        return MontgomeryContext(modulus, L)

    @staticmethod
    def for_secret_modulus(modulus, L):
        """M12. The same context, for odd modulus > 1. The Rust constructor tests nothing, so
        an even modulus or 1 is outside its contract and outside the model's."""
        _need(0 <= modulus < R(L), "for_secret_modulus: modulus fits L limbs")
        _need(modulus & 1 == 1, "for_secret_modulus: an even modulus is outside the contract (M12)")
        _need(modulus > 1, "for_secret_modulus: modulus = 1 is outside the contract (M2c)")
        return MontgomeryContext(modulus, L)


def redc_normalize(t, modulus, n_prime, L):
    """M3. T*R^-1 mod n in [0, n), for T < n*R."""
    high, extra = redc(t, modulus, n_prime, L)
    u = high + extra * R(L)
    return u - modulus if u >= modulus else u


def mont_mul(a, b, modulus, n_prime, L):
    """M4. a*b*R^-1 mod n, for a*b < n*R (in particular a, b < n)."""
    return redc_normalize(a * b, modulus, n_prime, L)


def mont_square(a, modulus, n_prime, L):
    return redc_normalize(a * a, modulus, n_prime, L)


def to_montgomery(a, ctx):
    """M4. a*R mod n for every a < R."""
    _need(0 <= a < R(ctx.L), "to_montgomery: a < R")
    return (a * R(ctx.L)) % ctx.modulus


def from_montgomery(a_bar, ctx):
    """M4. a_bar*R^-1 mod n for every a_bar < R."""
    _need(0 <= a_bar < R(ctx.L), "from_montgomery: a_bar < R")
    return (a_bar * pow(R(ctx.L), -1, ctx.modulus)) % ctx.modulus


def mul_mod(a, b, ctx):
    """M5. a*b mod n for a < R, b < n. (b >= n is outside the stated contract; b < R keeps
    T < n*R as well, which WP2 examines.)"""
    _need(0 <= a < R(ctx.L) and 0 <= b < ctx.modulus, "mul_mod: a < R, b < n")
    return (a * b) % ctx.modulus


def sub_mod(a, b, modulus, N):
    """M6. (a - b) mod m for a, b < m."""
    _need(0 < modulus < R(N) and 0 <= a < modulus and 0 <= b < modulus, "sub_mod: a, b < m")
    return (a - b) % modulus


def ct_shift_in_bit_mod(acc, bit, modulus, N):
    """M7. (2*acc + bit) mod m for every m >= 1 (odd or even), acc < m, bit in {0,1}."""
    _need(1 <= modulus < R(N) and 0 <= acc < modulus and bit in (0, 1), "ct_shift_in_bit_mod")
    return (2 * acc + bit) % modulus


def reduce_wide(value, modulus, WIDE, NARROW):
    """M8. value mod m for every m >= 1 and all widths."""
    _need(0 <= value < R(WIDE) and 1 <= modulus < R(NARROW), "reduce_wide: m >= 1")
    return value % modulus


def mod_pow(base, exponent, ctx):
    """M9. base^exponent mod n for odd n > 1, every exponent < R and every base < R; 0^0 = 1.
    (The Rust doc asks base < n and a debug build asserts it; M9 claims more.)"""
    _need(0 <= base < R(ctx.L) and 0 <= exponent < R(ctx.L), "mod_pow: base, exponent < R")
    return pow(base, exponent, ctx.modulus)


# =====================================================================================
# 3. crypto/rsa/src/codec.rs, rsa_core.rs                                 (E1, C1 - C6)
# =====================================================================================

def i2osp(x, x_len):
    """RFC 8017 section 4.1."""
    if x < 0 or x >= 256 ** x_len:                       # step 1
        raise ModelError("INTEGER_TOO_LARGE")
    return x.to_bytes(x_len, "big")                      # steps 2-3


def os2ip(octets):
    """RFC 8017 section 4.2."""
    return int.from_bytes(octets, "big")


def limbs_from_be_bytes(octets, L):
    """codec::limbs_from_be_bytes::<L, 8L>."""
    _need(len(octets) == 8 * L, "limbs_from_be_bytes: BYTES = 8L")
    return os2ip(octets)


def be_bytes_from_limbs(x, L):
    """codec::be_bytes_from_limbs::<L, 8L>."""
    _need(0 <= x < R(L), "be_bytes_from_limbs: fits L limbs")
    return i2osp(x, 8 * L)


def mod_pow_public_exponent(base, exponent, ctx):
    """M11. base^exponent mod n for odd n > 1, every base < R and every exponent < 2^64;
    exponent 0 gives 1."""
    _need(0 <= base < R(ctx.L) and 0 <= exponent < BETA, "mod_pow_public_exponent: base < R, e < 2^64")
    return pow(base, exponent, ctx.modulus)


def public_exp(n, e, x, L):
    """C5. x^e mod n (RSAEP / RSAVP1 step 2), for odd n > 1, x < R and a 64-bit e. The Rust
    function panics on an even n (documented); that is outside the contract here."""
    _need(n & 1 == 1 and 1 < n < R(L) and 0 <= x < R(L) and 0 <= e < BETA, "public_exp")
    return pow(x, e, n)


def crt_exp(p, q, d_p, d_q, q_inv, m, L, HALF):
    """RFC 8017 section 5.2.1 step 2.b (two primes), read literally:
         1. s_1 = m^dP mod p, s_2 = m^dQ mod q
         3. h = (s_1 - s_2) * qInv mod p
         4. s = s_2 + q*h
    Defined for everything the constructor admits (C3): odd p != q, dP < p, dQ < q, qInv < p.
    Under H_key it equals m^d mod n (C1); without it, it is whatever the three lines give.
    Returns s as an integer; C2 says s <= p*q - 1 < R(L)."""
    _need(L == 2 * HALF, "crt_exp: L = 2*HALF")
    Rh = R(HALF)
    _need(p & 1 and q & 1 and p != q and 0 < p < Rh and 0 < q < Rh, "crt_exp: odd p != q")
    _need(0 <= d_p < p and 0 <= d_q < q and 0 <= q_inv < p, "crt_exp: dP < p, dQ < q, qInv < p")
    _need(0 <= m < R(L), "crt_exp: m fits L limbs")
    s1 = pow(m % p, d_p, p)
    s2 = pow(m % q, d_q, q)
    h = ((s1 - s2) * q_inv) % p
    return s2 + q * h


def crt_exp_checked(p, q, d_p, d_q, q_inv, n, e, x, L, HALF):
    """C7, as a statement and not as the Rust steps: with y = crt_exp(...), the function
    returns (True, y) if y^e = x (mod n) and x < n, and (False, 0) otherwise. Nothing else.
    (For x >= n the comparison of the reduced y^e with x cannot succeed, so the answer is
    (False, 0): the Rust function's precondition x < n is not needed for the statement.)
    n is an argument, as in Rust; a key passes p*q. Odd n > 1, or public_exp is undefined."""
    y = crt_exp(p, q, d_p, d_q, q_inv, x, L, HALF)
    _need(n & 1 == 1 and 1 < n < R(L), "crt_exp_checked: odd n > 1")
    _need(0 <= e < BETA and y < R(L), "crt_exp_checked: 64-bit e, y fits")
    if pow(y, e, n) == x:
        return True, y
    return False, 0


class PublicComponents:
    """keys::RsaPublicComponents<K>::new, with K = k_len bytes of modulus."""

    def __init__(self, n, e, k_len):
        if n & 1 == 0:
            raise ModelError("DECODING", "RSA modulus must be odd")
        if e < 3 or e & 1 == 0:
            raise ModelError("DECODING", "RSA public exponent must be odd and at least 3")
        _need(0 <= n < 256 ** k_len and 0 <= e < BETA, "public key fits the size")
        self.n, self.e, self.k_len = n, e, k_len

    def encode(self):
        """n || e: K_LEN + 8 bytes since 6c58545 (e was four bytes at b7e46cb)."""
        return i2osp(self.n, self.k_len) + i2osp(self.e, 8)


class PrivateComponents:
    """A CRT private key as RFC 8017 section 3.2 has it, with the checks the Rust constructor
    made at b7e46cb, in its order. The modulus may be of any length here: this class also
    carries third-party test keys. What the constructor requires since the response (a
    full-length modulus, and the public exponent `e` the key now holds) is `key_private_new`
    in section 10; `e` is None for a key built without one."""

    def __init__(self, p, q, d_p, d_q, q_inv, k_len, e=None):
        half = 256 ** (k_len // 2)
        _need(all(0 <= v < half for v in (p, q, d_p, d_q, q_inv)), "components fit half width")
        if p & 1 == 0:
            raise ModelError("DECODING", "p must be odd")
        if q & 1 == 0:
            raise ModelError("DECODING", "q must be odd")
        if p == q:
            raise ModelError("DECODING", "p and q must be distinct")
        if not d_p < p:
            raise ModelError("DECODING", "dP must be less than p")
        if not d_q < q:
            raise ModelError("DECODING", "dQ must be less than q")
        if not q_inv < p:
            raise ModelError("DECODING", "qInv must be less than p")
        self.p, self.q, self.d_p, self.d_q, self.q_inv = p, q, d_p, d_q, q_inv
        self.n, self.k_len, self.e = p * q, k_len, e

    def encode(self):
        """p || q || dP || dQ || qInv || e: 5*K_LEN/2 + 8 bytes since 3f27178."""
        _need(self.e is not None, "encode: the key holds no public exponent")
        h = self.k_len // 2
        return b"".join(i2osp(v, h) for v in (self.p, self.q, self.d_p, self.d_q, self.q_inv)) \
            + i2osp(self.e, 8)

    def crt_exp(self, m):
        half = -(-self.k_len // 16)          # limbs per prime; vectors use sizes off the limb grid
        return crt_exp(self.p, self.q, self.d_p, self.d_q, self.q_inv, m, 2 * half, half)

    def h_key(self, e=None):
        """The plan's H_key, tested with Python arithmetic (primality is the caller's). Read
        with the `e` the key carries when none is given."""
        e = self.e if e is None else e
        p, q = self.p, self.q
        return (p != q and (e * self.d_p) % (p - 1) == 1 and (e * self.d_q) % (q - 1) == 1
                and (q * self.q_inv) % p == 1 and 0 < self.d_p < p and 0 < self.d_q < q
                and 0 < self.q_inv < p)


def rsasp1(sk, m):
    """RFC 8017 section 5.2.1. Step 1: m not in [0, n-1] is an error."""
    if not 0 <= m < sk.n:
        raise ModelError("DECODING", "message representative out of range")
    return sk.crt_exp(m)


def rsavp1(pk, s):
    """RFC 8017 section 5.2.2."""
    if not 0 <= s < pk.n:
        raise ModelError("DECODING", "signature representative out of range")
    return pow(s, pk.e, pk.n)


# =====================================================================================
# 4. Hashes and mask generation
# =====================================================================================

def _h(name):
    return lambda data=b"": hashlib.new(name, data)


class HashAlg:
    def __init__(self, name, ctor, out_len, digest_info_prefix=None, xof=False):
        self.name, self._ctor, self.out_len = name, ctor, out_len
        self.digest_info_prefix, self.xof = digest_info_prefix, xof

    def digest(self, data):
        return self._ctor(data).digest(self.out_len) if self.xof else self._ctor(data).digest()


def _hx(s):
    return bytes.fromhex(s.replace(" ", ""))


# DigestInfo prefixes: RFC 8017 section 9.2 note 1, transcribed; selftest.py re-reads them from
# the RFC text and compares. T = prefix || H.
_P = {
    "SHA-1": "30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14",
    "SHA-224": "30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04 05 00 04 1c",
    "SHA-256": "30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20",
    "SHA-384": "30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30",
    "SHA-512": "30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40",
    "SHA-512/224": "30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 05 05 00 04 1c",
    "SHA-512/256": "30 31 30 0d 06 09 60 86 48 01 65 03 04 02 06 05 00 04 20",
    # SHA-3: OIDs 2.16.840.1.101.3.4.2.{7,8,9,10} from NIST's registry. NOT read from a
    # document in this session; held to Wycheproof's rsa_signature_*_sha3_* valid vectors only.
    "SHA3-224": "30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 07 05 00 04 1c",
    "SHA3-256": "30 31 30 0d 06 09 60 86 48 01 65 03 04 02 08 05 00 04 20",
    "SHA3-384": "30 41 30 0d 06 09 60 86 48 01 65 03 04 02 09 05 00 04 30",
    "SHA3-512": "30 51 30 0d 06 09 60 86 48 01 65 03 04 02 0a 05 00 04 40",
}

HASHES = {
    "SHA-1": HashAlg("SHA-1", _h("sha1"), 20, _hx(_P["SHA-1"])),
    "SHA-224": HashAlg("SHA-224", _h("sha224"), 28, _hx(_P["SHA-224"])),
    "SHA-256": HashAlg("SHA-256", _h("sha256"), 32, _hx(_P["SHA-256"])),
    "SHA-384": HashAlg("SHA-384", _h("sha384"), 48, _hx(_P["SHA-384"])),
    "SHA-512": HashAlg("SHA-512", _h("sha512"), 64, _hx(_P["SHA-512"])),
    "SHA-512/224": HashAlg("SHA-512/224", _h("sha512_224"), 28, _hx(_P["SHA-512/224"])),
    "SHA-512/256": HashAlg("SHA-512/256", _h("sha512_256"), 32, _hx(_P["SHA-512/256"])),
    "SHA3-224": HashAlg("SHA3-224", _h("sha3_224"), 28, _hx(_P["SHA3-224"])),
    "SHA3-256": HashAlg("SHA3-256", _h("sha3_256"), 32, _hx(_P["SHA3-256"])),
    "SHA3-384": HashAlg("SHA3-384", _h("sha3_384"), 48, _hx(_P["SHA3-384"])),
    "SHA3-512": HashAlg("SHA3-512", _h("sha3_512"), 64, _hx(_P["SHA3-512"])),
    # RFC 8702 section 3.2.1: the message hash is the XOF read at 32 (SHAKE128) or 64 bytes.
    "SHAKE128": HashAlg("SHAKE128", _h("shake_128"), 32, None, xof=True),
    "SHAKE256": HashAlg("SHAKE256", _h("shake_256"), 64, None, xof=True),
}


def mgf1(hash_alg, mgf_seed, mask_len):
    """RFC 8017 appendix B.2.1, any seed length."""
    if mask_len > (1 << 32) * hash_alg.out_len:                       # step 1
        raise ModelError("MASK_TOO_LONG")
    t = b""                                                           # step 2
    for counter in range(-(-mask_len // hash_alg.out_len)):           # step 3
        t += hash_alg.digest(mgf_seed + i2osp(counter, 4))            # 3.A, 3.B
    return t[:mask_len]                                               # step 4


def shake_mask(hash_alg, mgf_seed, mask_len):
    """RFC 8702 section 3.2.1: "the SHAKEs MUST be used natively as the MGF"."""
    _need(hash_alg.xof, "shake_mask: a SHAKE")
    return hash_alg._ctor(mgf_seed).digest(mask_len)


class Mgf:
    """A mask generation function: MGF1 over a hash, or a SHAKE used natively."""

    def __init__(self, kind, hash_alg):
        _need(kind in ("mgf1", "shake"), "Mgf kind")
        self.kind, self.hash_alg = kind, hash_alg

    def __call__(self, seed, mask_len):
        if self.kind == "mgf1":
            return mgf1(self.hash_alg, seed, mask_len)
        return shake_mask(self.hash_alg, seed, mask_len)


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


# =====================================================================================
# 5. EMSA-PKCS1-v1_5                                                       (E2 - E4)
# =====================================================================================

def digest_info(hash_alg, digest):
    """RFC 8017 section 9.2 step 2: T, the DER DigestInfo, as note 1 gives it."""
    _need(hash_alg.digest_info_prefix is not None, "no DigestInfo for this hash")
    _need(len(digest) == hash_alg.out_len, "digest_info: one hash output")
    return hash_alg.digest_info_prefix + digest


def digest_info_absent_null(hash_alg, digest):
    """T with the AlgorithmIdentifier's parameters absent instead of NULL: not RFC 8017's T,
    but the second string the Rust verifier accepts (emsa_pkcs1_v1_5.rs:124-125). Derived from
    T by removing `05 00` and shortening the two SEQUENCE lengths by two."""
    t = digest_info(hash_alg, digest)
    pre = hash_alg.digest_info_prefix
    oid_end = 4 + 2 + pre[5]                    # 30 LL 30 II 06 OL <oid>
    assert pre[0] == 0x30 and pre[2] == 0x30 and pre[4] == 0x06
    assert pre[oid_end:oid_end + 2] == b"\x05\x00"
    return bytes([0x30, pre[1] - 2, 0x30, pre[3] - 2]) + t[4:oid_end] + t[oid_end + 2:]


def emsa_pkcs1_v1_5_encode_from_hash(hash_alg, digest, em_len, t=None):
    """RFC 8017 section 9.2 steps 2-5, from H."""
    t = digest_info(hash_alg, digest) if t is None else t            # step 2
    if em_len < len(t) + 11:                                         # step 3
        raise ModelError("ENCODED_LENGTH_TOO_SHORT")
    ps = b"\xff" * (em_len - len(t) - 3)                             # step 4
    return b"\x00\x01" + ps + b"\x00" + t                            # step 5


def emsa_pkcs1_v1_5_verify_strict(hash_alg, digest, em):
    """RFC 8017 section 8.2.2 steps 3-4: encode again and compare."""
    try:
        return em == emsa_pkcs1_v1_5_encode_from_hash(hash_alg, digest, len(em))
    except ModelError:
        return False


def emsa_pkcs1_v1_5_verify_from_hash(hash_alg, digest, em):
    """The accepted language claimed for the Rust verifier (E4): exactly two strings."""
    if emsa_pkcs1_v1_5_verify_strict(hash_alg, digest, em):
        return True
    try:
        alt = emsa_pkcs1_v1_5_encode_from_hash(
            hash_alg, digest, len(em), t=digest_info_absent_null(hash_alg, digest))
    except ModelError:
        return False
    return em == alt


# =====================================================================================
# 6. EMSA-PSS                                                              (E5 - E8)
# =====================================================================================

def emsa_pss_encode_from_hash(hash_alg, mgf, m_hash, salt, em_bits):
    """RFC 8017 section 9.1.1 steps 3-13, with mHash (step 2) and the salt (step 4) supplied.
    sLen is len(salt)."""
    h_len, s_len = hash_alg.out_len, len(salt)
    _need(len(m_hash) == h_len, "emsa_pss_encode: mHash is one hash output")
    em_len = -(-em_bits // 8)
    if em_len < h_len + s_len + 2:                                    # step 3
        raise ModelError("ENCODING_ERROR")
    m_prime = b"\x00" * 8 + m_hash + salt                             # step 5
    h = hash_alg.digest(m_prime)                                      # step 6
    ps = b"\x00" * (em_len - s_len - h_len - 2)                       # step 7
    db = ps + b"\x01" + salt                                          # step 8
    db_mask = mgf(h, em_len - h_len - 1)                              # step 9
    masked_db = bytearray(_xor(db, db_mask))                          # step 10
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)                    # step 11
    return bytes(masked_db) + h + b"\xbc"                             # step 12


def emsa_pss_verify_from_hash(hash_alg, mgf, m_hash, em, em_bits, s_len):
    """RFC 8017 section 9.1.2 steps 3-14."""
    h_len = hash_alg.out_len
    _need(len(m_hash) == h_len, "emsa_pss_verify: mHash is one hash output")
    em_len = -(-em_bits // 8)
    _need(len(em) == em_len, "emsa_pss_verify: EM has emLen octets")
    if em_len < h_len + s_len + 2:                                    # step 3
        return False
    if em[-1] != 0xBC:                                                # step 4
        return False
    masked_db, h = em[:em_len - h_len - 1], em[em_len - h_len - 1:-1]  # step 5
    top_mask = 0xFF >> (8 * em_len - em_bits)
    if masked_db[0] & ~top_mask & 0xFF:                               # step 6
        return False
    db = bytearray(_xor(masked_db, mgf(h, em_len - h_len - 1)))       # steps 7-8
    db[0] &= top_mask                                                 # step 9
    ps_len = em_len - h_len - s_len - 2
    if any(db[:ps_len]) or db[ps_len] != 0x01:                        # step 10
        return False
    salt = bytes(db[len(db) - s_len:]) if s_len else b""              # step 11
    m_prime = b"\x00" * 8 + m_hash + salt                             # step 12
    return h == hash_alg.digest(m_prime)                              # steps 13-14


# =====================================================================================
# 7. EME-OAEP                                                              (E9)
# =====================================================================================

def eme_oaep_encode(hash_alg, mgf, label, seed, msg, k):
    """RFC 8017 section 7.1.1 steps 1.b and 2, with the seed (step 2.d) supplied."""
    h_len = hash_alg.out_len
    _need(len(seed) == h_len, "eme_oaep_encode: seed is hLen octets")
    if len(msg) > k - 2 * h_len - 2:                                  # step 1.b
        raise ModelError("MESSAGE_TOO_LONG")
    l_hash = hash_alg.digest(label)                                   # 2.a
    ps = b"\x00" * (k - len(msg) - 2 * h_len - 2)                     # 2.b
    db = l_hash + ps + b"\x01" + msg                                  # 2.c
    masked_db = _xor(db, mgf(seed, k - h_len - 1))                    # 2.e, 2.f
    masked_seed = _xor(seed, mgf(masked_db, h_len))                   # 2.g, 2.h
    return b"\x00" + masked_seed + masked_db                          # 2.i


def eme_oaep_decode(hash_alg, mgf, label, em):
    """RFC 8017 section 7.1.2 step 3. Returns M, or None for "decryption error"."""
    h_len, k = hash_alg.out_len, len(em)
    if k < 2 * h_len + 2:                                             # step 1.c
        return None
    l_hash = hash_alg.digest(label)                                   # 3.a
    y, masked_seed, masked_db = em[0], em[1:1 + h_len], em[1 + h_len:]  # 3.b
    seed = _xor(masked_seed, mgf(masked_db, h_len))                   # 3.c, 3.d
    db = _xor(masked_db, mgf(seed, k - h_len - 1))                    # 3.e, 3.f
    l_hash_prime, rest = db[:h_len], db[h_len:]                       # 3.g
    i = 0
    while i < len(rest) and rest[i] == 0x00:
        i += 1
    if i == len(rest) or rest[i] != 0x01 or l_hash_prime != l_hash or y != 0:
        return None
    return rest[i + 1:]


# =====================================================================================
# 8. Schemes
# =====================================================================================

def rsassa_pkcs1_v1_5_sign(sk, hash_alg, msg):
    """RFC 8017 section 8.2.1."""
    em = emsa_pkcs1_v1_5_encode_from_hash(hash_alg, hash_alg.digest(msg), sk.k_len)
    return i2osp(rsasp1(sk, os2ip(em)), sk.k_len)


def rsassa_pkcs1_v1_5_verify(pk, hash_alg, msg, sig, lenient_null=False):
    """RFC 8017 section 8.2.2. `lenient_null` adds the absent-NULL encoding (the crate's
    verifier); without it this is the RFC's encode-and-compare."""
    if len(sig) != pk.k_len:                                          # step 1
        return False
    try:
        m = rsavp1(pk, os2ip(sig))                                    # 2.a, 2.b
        em = i2osp(m, pk.k_len)                                       # 2.c
    except ModelError:
        return False
    digest = hash_alg.digest(msg)
    if lenient_null:
        return emsa_pkcs1_v1_5_verify_from_hash(hash_alg, digest, em)
    return emsa_pkcs1_v1_5_verify_strict(hash_alg, digest, em)


def pss_em_bits(n, k_len, crate=False):
    """emBits = modBits - 1 (RFC 8017 section 8.1.1 step 1). The crate fixes it at
    8*K_LEN - 1 whatever the modulus's true bit length (emsa_pss.rs:71, 100)."""
    return 8 * k_len - 1 if crate else n.bit_length() - 1


def rsassa_pss_sign(sk, hash_alg, mgf, msg, salt, crate_em_bits=False):
    """RFC 8017 section 8.1.1 with the salt supplied."""
    em_bits = pss_em_bits(sk.n, sk.k_len, crate_em_bits)
    em = emsa_pss_encode_from_hash(hash_alg, mgf, hash_alg.digest(msg), salt, em_bits)
    return i2osp(rsasp1(sk, os2ip(em)), sk.k_len)                     # steps 2.a-2.c


def rsassa_pss_verify(pk, hash_alg, mgf, msg, sig, s_len, crate_em_bits=False):
    """RFC 8017 section 8.1.2."""
    if len(sig) != pk.k_len:                                          # step 1
        return False
    em_bits = pss_em_bits(pk.n, pk.k_len, crate_em_bits)
    try:
        m = rsavp1(pk, os2ip(sig))                                    # 2.a, 2.b
        em = i2osp(m, -(-em_bits // 8))                               # 2.c
    except ModelError:
        return False
    return emsa_pss_verify_from_hash(hash_alg, mgf, hash_alg.digest(msg), em, em_bits, s_len)


def in_open_range(x, n):
    """rsasve::in_open_range: 1 < x < n - 1."""
    return 1 < x < n - 1


def rsaes_oaep_encrypt(pk, hash_alg, mgf, label, msg, seed):
    """RFC 8017 section 7.1.1 with the seed supplied."""
    em = eme_oaep_encode(hash_alg, mgf, label, seed, msg, pk.k_len)    # steps 1-2
    m = os2ip(em)                                                     # 3.a
    if not 0 <= m < pk.n:                                             # RSAEP step 1
        raise ModelError("MESSAGE_REPRESENTATIVE_OUT_OF_RANGE")
    return i2osp(pow(m, pk.e, pk.n), pk.k_len)                        # 3.b, 3.c


def rsaes_oaep_decrypt(sk, hash_alg, mgf, label, ct, sp80056b_range=True):
    """RFC 8017 section 7.1.2. Returns M or None. With `sp80056b_range` the ciphertext must
    satisfy 1 < c < n - 1 (SP 800-56B Rev. 2 section 7.1.2 [extraction]; the crate's choice,
    rsaes_oaep.rs:218-226); without it, RFC 8017's c < n."""
    if len(ct) != sk.k_len:                                           # step 1.b
        return None
    c = os2ip(ct)                                                     # 2.a
    ok = in_open_range(c, sk.n) if sp80056b_range else 0 <= c < sk.n
    if not ok:
        return None
    em = i2osp(sk.crt_exp(c), sk.k_len)                               # 2.b, 2.c
    return eme_oaep_decode(hash_alg, mgf, label, em)                  # step 3


class StreamRng:
    """A byte stream as an RNG: both sides of a differential run read the same bytes."""

    def __init__(self, data, strength=256):
        self.data, self.pos, self.strength, self.calls = data, 0, strength, 0

    def next_bytes(self, n):
        self.calls += 1
        if self.pos + n > len(self.data):
            raise ModelError("RNG_ERROR", "stream exhausted")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out


RSASVE_MAX_GENERATE_ATTEMPTS = 128      # rsasve::MAX_GENERATE_ATTEMPTS; the SP's loop is unbounded


def rsasve_generate(pk, rng):
    """SP 800-56B Rev. 2 section 7.2.1.2 [extraction]: Z = nLen bytes from the RBG,
    z = BS2I(Z), repeat unless 1 < z < n - 1; c = z^e mod n; C = I2BS(c, nLen).
    Returns (Z, C). The crate gives up after 128 draws."""
    for _ in range(RSASVE_MAX_GENERATE_ATTEMPTS):
        z_bytes = rng.next_bytes(pk.k_len)
        z = os2ip(z_bytes)
        if in_open_range(z, pk.n):
            return z_bytes, i2osp(pow(z, pk.e, pk.n), pk.k_len)
    raise ModelError("GENERIC", "RSASVE.GENERATE: RNG output never fell within (1, n - 1)")


def rsasve_recover(sk, ct):
    """SP 800-56B Rev. 2 section 7.2.1.3 [extraction]: c = BS2I(C); 1 < c < n - 1 or error;
    z = RSADP(c); Z = I2BS(z, nLen)."""
    if len(ct) != sk.k_len:
        raise ModelError("LENGTH")
    c = os2ip(ct)
    if not in_open_range(c, sk.n):
        raise ModelError("DECAPSULATION_FAILED")
    return i2osp(sk.crt_exp(c), sk.k_len)


def hkdf_extract(hash_name, salt, ikm):
    """RFC 5869 section 2.2. An absent salt is HashLen zero octets."""
    h_len = hashlib.new(hash_name).digest_size
    return _hmac.new(salt if salt else b"\x00" * h_len, ikm, hash_name).digest()


def hkdf_expand(hash_name, prk, info, length):
    """RFC 5869 section 2.3."""
    h_len = hashlib.new(hash_name).digest_size
    if length > 255 * h_len:
        raise ModelError("KDF_LENGTH")
    t, okm = b"", b""
    for i in range(1, -(-length // h_len) + 1):
        t = _hmac.new(prk, t + info + bytes([i]), hash_name).digest()
        okm += t
    return okm[:length]


def hkdf(hash_name, salt, ikm, info, length):
    return hkdf_expand(hash_name, hkdf_extract(hash_name, salt, ikm), info, length)


def rsasve_hkdf_derive(hash_name, salt, z_bytes, info, ss_len):
    """rsasve_kdf::derive: HKDF-Hash(salt, Z, info) to SS_LEN bytes, 1 <= SS_LEN <= 255*hLen."""
    _need(ss_len > 0, "the derived key has at least one byte")
    return hkdf(hash_name, salt, z_bytes, info, ss_len)


# =====================================================================================
# 9. crypto/rsa/src/keygen.rs                                             (K1 - K11)
# =====================================================================================

PUBLIC_EXPONENT = 65537
SMALL_PRIME_LIMIT = 1024


def _small_primes(limit):
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i in range(limit) if sieve[i]]


SMALL_PRIMES = _small_primes(SMALL_PRIME_LIMIT)


def mod_u64(a, m):
    _need(0 < m < BETA, "mod_u64")
    return a % m


def mul_u64_add(a, k, add, N):
    """(out, carry) with out + carry*R = a*k + add."""
    t = a * k + add
    return t % R(N), t >> (64 * N)


def div_u64(hi, a, d, N):
    """((hi*R + a) div d, (hi*R + a) mod d) for hi < d."""
    _need(0 <= hi < d < BETA and 0 <= a < R(N), "div_u64: hi < d")
    return divmod(hi * R(N) + a, d)


def inv_mod_u64_prime(r, e):
    """K6. r^-1 mod e for prime e, 0 < r < e."""
    _need(0 < r < e, "inv_mod_u64_prime")
    return pow(r, -1, e)


def inverse_of_e_mod(m, N):
    """K5. e^-1 mod m for m > 1, gcd(m, e) = 1, e = 65537."""
    _need(1 < m < R(N) and m % PUBLIC_EXPONENT != 0, "inverse_of_e_mod: e does not divide m")
    return pow(PUBLIC_EXPONENT, -1, m)


def gcd(a, b, N):
    """K4."""
    import math
    _need(0 <= a < R(N) and 0 <= b < R(N), "gcd operands")
    return math.gcd(a, b)


def div(a, d, N):
    """K4. floor(a / d), d != 0."""
    _need(0 <= a < R(N) and 0 < d < R(N), "div: d != 0")
    return a // d


def has_small_factor(w, N):
    """K10. Some prime below 1024 divides w, other than w itself."""
    _need(0 <= w < R(N), "has_small_factor operand")
    return any(w % p == 0 and w != p for p in SMALL_PRIMES)


def fill_random(rng, N):
    """keygen::fill_random: N draws of 8 bytes; draw i is limb i, read big-endian."""
    return from_limbs([int.from_bytes(rng.next_bytes(8), "big") for _ in range(N)])


def is_probable_prime(w, rounds, rng, N):
    """K11. FIPS 186-5 B.3.1 [extraction], behind trial division, in the Rust order of draws.
    True is PROBABLY PRIME."""
    _need(0 <= w < R(N) and rounds >= 1, "is_probable_prime")
    if w in (0, 1):
        return False
    if w & 1 == 0:
        return w == 2
    if w < SMALL_PRIME_LIMIT * SMALL_PRIME_LIMIT:
        return not has_small_factor(w, N)
    if has_small_factor(w, N):
        return False
    a = ((w - 1) & -(w - 1)).bit_length() - 1                         # step 1
    m = (w - 1) >> a                                                  # step 2
    wlen = w.bit_length()                                             # step 3
    for _ in range(rounds):                                           # step 4
        for _ in range(128):                                          # 4.1, 4.2
            b = fill_random(rng, N) & ((1 << wlen) - 1)
            if 1 < b < w - 1:
                break
        else:
            raise ModelError("GENERIC", "RNG produced no usable Miller-Rabin base in 128 draws")
        z = pow(b, m, w)                                              # 4.3
        if z == 1 or z == w - 1:                                      # 4.4
            continue
        witness = True
        for _ in range(1, a):                                         # 4.5
            z = (z * z) % w
            if z == w - 1:
                witness = False
                break
            if z == 1:
                break
        if witness:
            return False                                              # 4.6
    return True                                                       # step 5


def candidate(rng, N):
    """keygen::candidate: 64N random bits, the two top bits and the low bit set
    (FIPS 186-5 A.1.3 steps 4.2, 4.2.1, 4.3 [extraction])."""
    return fill_random(rng, N) | (0b11 << (64 * N - 2)) | 1


def primes_too_close(p, q, N):
    """K3. |p - q| <= 2^(64N - 100)."""
    return abs(p - q) <= 1 << (64 * N - 100)


def random_prime(rng, rounds, max_attempts, N, extra_check=lambda c: True):
    """keygen::random_prime. A candidate rejected by `extra_check` (step 5.5) counts toward
    `max_attempts`: the Rust behaviour; FIPS 186-5 does not count it [extraction]."""
    for _ in range(max_attempts):
        c = candidate(rng, N)
        if not extra_check(c):
            continue
        if c % PUBLIC_EXPONENT == 1:
            continue
        if is_probable_prime(c, rounds, rng, N):
            return c
    raise ModelError("GENERIC", "candidate limit")


def d_exceeds_half(d, HALF):
    """K7. d > 2^(nlen/2)."""
    return d > 1 << (64 * HALF)


def keygen_from_rng(rng, rounds, required_strength, HALF):
    """keygen::keygen_from_rng. Returns (PublicComponents, PrivateComponents)."""
    import math
    if rng.strength < required_strength:
        raise ModelError("RNG_STRENGTH")
    nlen = 128 * HALF
    while True:
        p = random_prime(rng, rounds, 5 * nlen, HALF)
        q = random_prime(rng, rounds, 10 * nlen, HALF, lambda c: not primes_too_close(p, c, HALF))
        g = math.gcd(p - 1, q - 1)
        lcm = (p - 1) * ((q - 1) // g)
        d = pow(PUBLIC_EXPONENT, -1, lcm)
        if not d_exceeds_half(d, HALF):
            continue
        d_p = pow(PUBLIC_EXPONENT, -1, p - 1)
        d_q = pow(PUBLIC_EXPONENT, -1, q - 1)
        q_inv = pow(q % p, p - 2, p)                  # as the code computes it; q^-1 iff p prime
        k_len = 16 * HALF
        sk = key_private_new(p, q, d_p, d_q, q_inv, PUBLIC_EXPONENT, k_len)
        return key_public_new(sk.n, PUBLIC_EXPONENT, k_len), sk


def check_a11_criteria(nlen, e, p, q, d=None):
    """FIPS 186-5 appendix A.1.1 [extraction], the checks that do not need a primality proof.
    Returns the list of criteria that fail (empty when all hold)."""
    import math
    half = nlen // 2
    fails = []
    if not (e & 1 and (1 << 16) < e < (1 << 256)):
        fails.append("1(b) e odd, 2^16 < e < 2^256")
    if math.gcd(p - 1, e) != 1 or math.gcd(q - 1, e) != 1:
        fails.append("2(a) gcd(p-1, e) = gcd(q-1, e) = 1")
    # sqrt(2)*2^(half-1) <= x  <=>  2^(2*half-1) <= x^2
    for name, x in (("2(b) p", p), ("2(c) q", q)):
        if not ((1 << (2 * half - 1)) <= x * x and x <= (1 << half) - 1):
            fails.append(f"{name} in [sqrt(2)*2^(nlen/2-1), 2^(nlen/2)-1]")
    if not abs(p - q) > 1 << (half - 100):
        fails.append("2(d) |p - q| > 2^(nlen/2-100)")
    lcm = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    d_ref = pow(e, -1, lcm) if math.gcd(e, lcm) == 1 else None
    if d_ref is None or not ((1 << half) < d_ref < lcm):
        fails.append("3(a) 2^(nlen/2) < d < lcm(p-1, q-1)")
    if d is not None and d != d_ref:
        fails.append("3(b) d = e^-1 mod lcm(p-1, q-1)")
    if (p * q).bit_length() != nlen:
        fails.append("n has nlen bits")
    return fails


# =====================================================================================
# 10. The crate layer: what the Rust API answers where the specification is silent
#                                                     (I1, I2, C7, E11, K16; WP14.3)
# =====================================================================================
# Read in the source at 30cbbab: keys.rs (the constructors and `validated`), rsasve.rs (the
# key-establishment wrappers), rsassa.rs and the two emsa files (the length rules),
# rsa_core.rs (`rsasp1`, `crt_exp_checked`), keygen.rs (`fill_bytes`). Error texts are the
# crate's, compared as text by the differential run, so a reworded message shows as a
# mismatch to settle by hand; the verdicts are what the obligations are about.

MSG_N_EVEN = "RSA modulus must be odd"
MSG_N_SHORT = "RSA modulus must have its top bit set"
MSG_E = "RSA public exponent must be odd and at least 3"
MSG_KEM_E = "RSA key-establishment public exponent must be at least 65537"
MSG_HASH_LEN = "the message hash must be the hash's output length"
MSG_SALT_LEN = "the salt must be the parameters' salt length"
MSG_PSS_TOO_SHORT = "the modulus is too short for this hash and salt length"
KEM_MIN_PUBLIC_EXPONENT = 65537


def i1_public(n, e, bits):
    """Plan obligation I1, public half, as a predicate and in no particular order: n odd,
    2^(bits-1) <= n < 2^bits, e odd, 3 <= e < 2^64."""
    return n & 1 == 1 and (1 << (bits - 1)) <= n < (1 << bits) and e & 1 == 1 and 3 <= e < BETA


def i1_private(p, q, d_p, d_q, q_inv, e, bits):
    """Plan obligation I1, private half: p != q odd, dP < p, dQ < q, qInv < p,
    p*q >= 2^(bits-1), e as for the public half. (p, q < 2^(bits/2) by their type.)"""
    return (p & 1 == 1 and q & 1 == 1 and p != q and 0 <= d_p < p and 0 <= d_q < q
            and 0 <= q_inv < p and p * q >= (1 << (bits - 1)) and e & 1 == 1 and 3 <= e < BETA)


def key_public_new(n, e, k_len):
    """keys::RsaPublicComponents::new at 30cbbab, checks in the Rust order: parity of n, its
    top bit, then e."""
    _need(0 <= n < 256 ** k_len and 0 <= e < BETA, "key_public_new: n fits K_LEN bytes, e 64 bits")
    if n & 1 == 0:
        raise ModelError("DECODING", MSG_N_EVEN)
    if n >> (8 * k_len - 1) == 0:
        raise ModelError("DECODING", MSG_N_SHORT)
    if e < 3 or e & 1 == 0:
        raise ModelError("DECODING", MSG_E)
    return PublicComponents(n, e, k_len)


def key_private_new(p, q, d_p, d_q, q_inv, e, k_len):
    """keys::RsaPrivateComponents::validated at 30cbbab, checks in the Rust order: e; the
    parity of p, of q; p != q; dP < p; dQ < q; qInv < p; then the top bit of p*q."""
    half = 256 ** (k_len // 2)
    _need(all(0 <= v < half for v in (p, q, d_p, d_q, q_inv)) and 0 <= e < BETA,
          "key_private_new: components fit half width, e 64 bits")
    if e < 3 or e & 1 == 0:
        raise ModelError("DECODING", MSG_E)
    sk = PrivateComponents(p, q, d_p, d_q, q_inv, k_len, e)      # the five checks, in order
    if sk.n >> (8 * k_len - 1) == 0:
        raise ModelError("DECODING", MSG_N_SHORT)
    return sk


def kem_public_new(n, e, k_len):
    """rsasve::RsaKEMPublicKey::new: the components' checks, then e >= 65537."""
    pk = key_public_new(n, e, k_len)
    if e < KEM_MIN_PUBLIC_EXPONENT:
        raise ModelError("DECODING", MSG_KEM_E)
    return pk


def kem_private_new(p, q, d_p, d_q, q_inv, e, k_len):
    """rsasve::RsaKEMPrivateKey::from_crt_components: the components' checks, then e >= 65537."""
    sk = key_private_new(p, q, d_p, d_q, q_inv, e, k_len)
    if e < KEM_MIN_PUBLIC_EXPONENT:
        raise ModelError("DECODING", MSG_KEM_E)
    return sk


def key_public_decode(octets, k_len):
    """PublicKey::from_bytes: n || e at K_LEN + 8 bytes, validated as the constructor does."""
    if len(octets) != k_len + 8:
        raise ModelError("KEY_LENGTH")
    return key_public_new(os2ip(octets[:k_len]), os2ip(octets[k_len:]), k_len)


def key_private_decode(octets, k_len):
    """PrivateKey::from_bytes: p || q || dP || dQ || qInv || e at 5*K_LEN/2 + 8 bytes."""
    h = k_len // 2
    if len(octets) != 5 * h + 8:
        raise ModelError("KEY_LENGTH")
    parts = [os2ip(octets[i * h:(i + 1) * h]) for i in range(5)]
    return key_private_new(*parts, os2ip(octets[5 * h:]), k_len)


def rsasp1_checked(sk, m):
    """rsa_core::rsasp1 since 3f27178: the range check of RFC 8017 section 5.2.1 step 1, then
    the checked CRT; a result that fails its check is an error and nothing is returned."""
    _need(sk.e is not None and sk.k_len % 16 == 0, "rsasp1_checked: a key with e, on the limb grid")
    if not 0 <= m < sk.n:
        raise ModelError("DECODING", "message representative out of range")
    half = sk.k_len // 16
    ok, y = crt_exp_checked(sk.p, sk.q, sk.d_p, sk.d_q, sk.q_inv, sk.n, sk.e, m, 2 * half, half)
    if not ok:
        raise ModelError("COMPUTATION_FAULT")
    return y


def crate_emsa_v15_encode(hash_alg, m_hash, k_len):
    """RsaDeterministicSignatureAlgorithm::emsa_encode for RSASSA-PKCS1-v1_5 (E11): a hash of
    the wrong length is LengthError. K_LEN >= tLen + 11 is a debug assertion in the crate
    (E3), so a pairing that breaks it is outside the contract."""
    if len(m_hash) != hash_alg.out_len:
        raise ModelError("LENGTH", MSG_HASH_LEN)
    _need(k_len >= len(hash_alg.digest_info_prefix) + hash_alg.out_len + 11, "E3: K_LEN >= tLen + 11")
    return emsa_pkcs1_v1_5_encode_from_hash(hash_alg, m_hash, k_len)


def crate_emsa_v15_verify(hash_alg, m_hash, em):
    """emsa_verify for RSASSA-PKCS1-v1_5: false for a hash of the wrong length."""
    if len(m_hash) != hash_alg.out_len:
        return False
    return emsa_pkcs1_v1_5_verify_from_hash(hash_alg, m_hash, em)


def crate_emsa_pss_encode(hash_alg, mgf, m_hash, salt, s_len, k_len):
    """emsa_encode for RSASSA-PSS (E11), checks in the Rust order: the hash's length, the
    salt's, then RFC 8017 section 9.1.1 step 3. emBits is 8*K_LEN - 1, which is modBits - 1
    for every key the constructors admit (I1; E6)."""
    if len(m_hash) != hash_alg.out_len:
        raise ModelError("LENGTH", MSG_HASH_LEN)
    if len(salt) != s_len:
        raise ModelError("LENGTH", MSG_SALT_LEN)
    if k_len < hash_alg.out_len + s_len + 2:
        raise ModelError("ENCODING", MSG_PSS_TOO_SHORT)
    return emsa_pss_encode_from_hash(hash_alg, mgf, m_hash, salt, 8 * k_len - 1)


def crate_emsa_pss_verify(hash_alg, mgf, m_hash, em, s_len):
    """emsa_verify for RSASSA-PSS: false for a hash of the wrong length."""
    if len(m_hash) != hash_alg.out_len:
        return False
    return emsa_pss_verify_from_hash(hash_alg, mgf, m_hash, em, 8 * len(em) - 1, s_len)


def crate_sign_from_hash_v15(sk, hash_alg, m_hash):
    """rsassa::sign_from_hash_deterministic for RSASSA-PKCS1-v1_5."""
    em = crate_emsa_v15_encode(hash_alg, m_hash, sk.k_len)
    return i2osp(rsasp1_checked(sk, os2ip(em)), sk.k_len)


def crate_sign_from_hash_pss(sk, hash_alg, mgf, m_hash, salt, s_len):
    """rsassa::sign_from_hash_with_salt (s_len > 0) and sign_from_hash_deterministic for the
    unsalted parameters (s_len = 0, salt empty)."""
    em = crate_emsa_pss_encode(hash_alg, mgf, m_hash, salt, s_len, sk.k_len)
    return i2osp(rsasp1_checked(sk, os2ip(em)), sk.k_len)


def crate_sign_from_hash_pss_rng(sk, hash_alg, mgf, m_hash, s_len, rng):
    """rsassa::sign_from_hash: the hash's length is checked before anything is drawn, then
    the salt is one draw of s_len bytes."""
    if len(m_hash) != hash_alg.out_len:
        raise ModelError("LENGTH", MSG_HASH_LEN)
    salt = rng.next_bytes(s_len)
    return crate_sign_from_hash_pss(sk, hash_alg, mgf, m_hash, salt, s_len)


def crate_verify_from_hash(pk, hash_alg, m_hash, sig, verify_em):
    """rsassa::verify_from_hash: the hash's length (LengthError), RSAVP1's range check
    (DecodingError), then the scheme's verification of EM, `verify_em(m_hash, em)`."""
    if len(m_hash) != hash_alg.out_len:
        raise ModelError("LENGTH", MSG_HASH_LEN)
    _need(len(sig) == pk.k_len, "verify_from_hash: the signature is K_LEN bytes by its type")
    em = i2osp(rsavp1(pk, os2ip(sig)), pk.k_len)
    if not verify_em(m_hash, em):
        raise ModelError("VERIFICATION_FAILED")
    return True


def fill_bytes(length, claim):
    """K16. keygen::fill_bytes against an RNG that reports `claim` bytes written (None: an
    error of its own): True exactly when claim == length; on anything else the caller gets an
    error and the buffer is zero."""
    return claim is not None and claim == length
