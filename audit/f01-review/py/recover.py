#!/usr/bin/env python3
"""
Recover a CRT prime from the real branch decisions Harness A recorded.

Reads recover_input.txt (emitted by the Rust harness):
    n=<hex>          public modulus p*q
    p=<hex>, q=<hex> true primes, for self-checking only
    T=2048           number of doublings in the R^2 pow2_mod call
    r2bits_p=0101..  the T decisions MontgomeryContext::new(p) made in that call
    r2bits_q=...     same for new(q)

For each prime, Q = floor(2^T / prime) is read straight off the decision bits (the lemma proved
in lemma.py), giving prime in ( 2^T/(Q+1), 2^T/Q ]; the prime is recovered as the unique divisor
of the PUBLIC n in that interval, with no prior knowledge of the prime. Prints PASS iff the
recovered value equals the true prime the harness also emitted.
"""
import sys


def read_kv(path):
    d = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                d[k] = v
    return d


def bits_to_Q(bitstr):
    Q = 0
    for ch in bitstr:
        Q = 2 * Q + (1 if ch == "1" else 0)
    return Q


def recover(prime_name, bitstr, T, n, true_prime):
    Q = bits_to_Q(bitstr)
    assert len(bitstr) == T, f"{prime_name}: expected {T} decision bits, got {len(bitstr)}"
    lo = (1 << T) // (Q + 1) + 1
    hi = (1 << T) // Q
    width = hi - lo + 1
    # recover as the unique divisor of the public modulus inside the interval
    divisors = [m for m in range(lo, hi + 1) if n % m == 0]
    rec = divisors[0] if len(divisors) == 1 else None
    ok = rec == true_prime
    # also report how well floor(2^T/prime) was reconstructed, independent of the divisor step
    q_matches = (Q == (1 << T) // true_prime)
    print(f"  {prime_name}: Q==floor(2^T/{prime_name})={q_matches}  interval width={width}  "
          f"recovered=={prime_name}: {ok}")
    return ok


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "recover_input.txt"
    d = read_kv(path)
    n = int(d["n"], 16)
    p = int(d["p"], 16)
    q = int(d["q"], 16)
    T = int(d["T"])
    assert p * q == n, "sanity: p*q must equal the emitted n"
    ok_p = recover("p", d["r2bits_p"], T, n, p)
    ok_q = recover("q", d["r2bits_q"], T, n, q)
    if ok_p and ok_q:
        print("PASS recover-real-code   : p and q recovered from the real new()'s R^2 branch decisions")
        print("RECOVER-ALL-PASS")
    else:
        print("FAIL recover-real-code")
        print("RECOVER-FAIL")
        sys.exit(1)


if __name__ == "__main__":
    main()
