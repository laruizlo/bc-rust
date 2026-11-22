#!/usr/bin/env python3
"""
Lemma and demonstration for finding F-01 (second review).

double_mod_n(a, n) computes 2a mod n for a < n, odd n, via:
    (doubled, carry) = a + a           # carry = did 2a overflow 64L bits
    (diff, borrow)   = doubled - n     # borrow = 0 iff doubled >= n
    result = diff   if (carry == 1 or borrow == 0)   # i.e. iff 2a >= n
             doubled otherwise
pow2_mod(T, n): acc = 1; repeat T times acc = double_mod_n(acc, n); returns 2^T mod n.
MontgomeryContext::new(n) calls pow2_mod(64*L, n) for R mod n and pow2_mod(128*L, n) for R^2 mod n.

The per-step decision b_i := [2*acc_{i-1} >= n] (1 = "a subtraction of n happened") is exactly
what the source-level `if` in double_mod_n branches on.

LEMMA (quotient digits).  With a_0 = 1, a_i = 2*a_{i-1} - b_i*n, and Q_i := floor(2^i / n):
    Q_0 = 0,  Q_i = 2*Q_{i-1} + b_i,   so  (b_1,...,b_i) is the binary expansion of floor(2^i/n).
Proof: 2^i = 2*(Q_{i-1} n + a_{i-1}) = 2Q_{i-1} n + 2a_{i-1}; 0 <= a_{i-1} < n so 0 <= 2a_{i-1} < 2n,
hence exactly one conditional subtraction yields 0 <= a_i < n, and b_i is that subtraction, giving
Q_i = 2Q_{i-1} + b_i and a_i = 2^i mod n.  QED.

Consequence: observing the T decisions of pow2_mod(T, n) yields Q_T = floor(2^T / n), from which
    n in ( 2^T/(Q_T + 1),  2^T/Q_T ].
For the R^2 call T = 128*L = 2*(bitlen of n) (n has 64L-bit width, top bit set), the interval has
width about 1, so n is recovered essentially exactly.  This file verifies that end to end on a real
1024-bit RSA prime (L = 16, the RSA-2048 CRT width).
"""

import random

MASK64 = (1 << 64) - 1


def double_mod_n(a, n, L):
    """Faithful big-int model of modexp.rs double_mod_n; returns (result, b) with b the branch bit."""
    doubled_full = a + a
    carry = 1 if doubled_full >> (64 * L) else 0
    doubled = doubled_full & ((1 << (64 * L)) - 1)
    borrow = 0 if doubled >= n else 1          # diff = doubled - n borrows iff doubled < n
    if carry == 1 or borrow == 0:
        # value >= n: subtract once.  Note when carry==1, diff = (2a) - n taken over 64L bits
        return (doubled - n) & ((1 << (64 * L)) - 1), 1
    return doubled, 0


def pow2_mod_traced(T, n, L):
    """pow2_mod(T, n); returns (2^T mod n, [b_1..b_T])."""
    acc = 1
    bits = []
    for _ in range(T):
        acc, b = double_mod_n(acc, n, L)
        bits.append(b)
    return acc, bits


def recover_from_bits(bits, T):
    """Q_T = floor(2^T/n) read straight off the decision bits; then the modulus interval."""
    Q = 0
    for b in bits:
        Q = 2 * Q + b
    # n in ( 2^T/(Q+1), 2^T/Q ]
    lo = (1 << T) // (Q + 1) + 1
    hi = (1 << T) // Q
    return Q, lo, hi


def is_probable_prime(m):
    if m < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if m % p == 0:
            return m == p
    d = m - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, m)
        if x in (1, m - 1):
            continue
        for _ in range(r - 1):
            x = x * x % m
            if x == m - 1:
                break
        else:
            return False
    return True


def gen_prime_1024(rng):
    """A 1024-bit prime with the top two bits set, as keygen::candidate builds (out[N-1] |= 0b11<<62)."""
    while True:
        c = rng.getrandbits(1024)
        c |= (0b11 << 1022)   # top two bits of the 1024-bit number
        c |= 1                # odd
        if is_probable_prime(c):
            return c


def main():
    rng = random.Random(0xF01_5EED)
    L = 16                     # RSA-2048 CRT prime width (16 limbs = 1024 bits)
    ok = True

    # Sanity: a_i == 2^i mod n and Q from bits == floor(2^i/n), on a small modulus.
    n_small = 1009
    acc, bits = pow2_mod_traced(40, n_small, 1)
    assert acc == pow(2, 40, n_small), "a_T must equal 2^T mod n"
    Qchk = 0
    for i, b in enumerate(bits, 1):
        Qchk = 2 * Qchk + b
        assert Qchk == (1 << i) // n_small, f"Q_{i} mismatch"
    print("PASS lemma-identities   : b-sequence equals binary expansion of floor(2^i/n) (small-n check)")

    # End-to-end recovery of a real 1024-bit prime from the R^2 call's decision pattern.
    # Threat model: attacker holds public n = p*q, and observes the T decision bits of the
    # pow2_mod(128*L, p) call (one of the two MontgomeryContext::new(p) builds a signature does).
    recovered_all = True
    for trial in range(5):
        p = gen_prime_1024(rng)
        q = gen_prime_1024(rng)
        n = p * q                               # public modulus
        T = 128 * L                             # the pow2_mod(128*L, p) call: R^2 mod p
        _, bits = pow2_mod_traced(T, p, L)      # the per-step branch decisions, as an attacker sees them
        Q, lo, hi = recover_from_bits(bits, T)
        assert Q == (1 << T) // p
        width = hi - lo + 1
        inside = lo <= p <= hi
        # Recover p with no prior knowledge of p: the unique divisor of public n in [lo, hi].
        divisors = [m for m in range(lo, hi + 1) if n % m == 0]
        p_rec = divisors[0] if len(divisors) == 1 else None
        got = (p_rec == p)
        recovered_all &= inside and got
        print(f"  trial {trial}: interval width = {width:>2}  p in interval = {inside}  "
              f"unique divisor of n in interval == p = {got}")
    if recovered_all:
        print("PASS recover-prime-R2    : floor(2^128L/p) from the R^2 decision bits + public n recovers p")
    else:
        print("FAIL recover-prime-R2")
        ok = False

    # The R-only call (64*L doublings) leaks almost nothing by itself: show its interval is huge.
    p = gen_prime_1024(rng)
    _, bitsR = pow2_mod_traced(64 * L, p, L)
    QR, loR, hiR = recover_from_bits(bitsR, 64 * L)
    widthR = hiR - loR + 1
    big = widthR > (1 << 1000)
    print(f"INFO R-only call         : floor(2^64L/p) interval width ~ 2^{widthR.bit_length()-1} "
          f"(leak is carried by the R^2 call, not this one)")
    if not big:
        print("NOTE: expected the R-only interval to be wide")

    print("ALL-PASS" if ok and recovered_all else "SOME-FAIL")


if __name__ == "__main__":
    main()
