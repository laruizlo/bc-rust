#!/usr/bin/env python3
"""The order in which key generation reads its random bytes: finding F-05, row 3 (plan WP14.4).

    python3 -I audit/ref/limb_order_check.py --runner audit/harness/target/release/diff_runner

`keygen.rs` documents `fill_random` since 2e53d0b as: eight bytes to a limb in the order drawn,
the first eight bytes limb 0 (the least significant), each eight big-endian within their limb.
At the first pass the comment said the string was read as one big-endian integer, which the
code did not do.

One byte stream goes to the crate's key generation (RSA-2048, through `diff_runner`) and to
the model three times: reading it as the comment now says, as the comment said then, and with
the bytes of a limb reversed. The key must be the first reading's, bit for bit, and neither
of the others: the differential that fixes the order, with the control that it could tell.
"""
import argparse
import os
import random
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rsa_ref as M  # noqa: E402

READINGS = {
    "as documented now: draw i is limb i, big-endian within the limb":
        lambda rng, N: M.from_limbs([int.from_bytes(rng.next_bytes(8), "big") for _ in range(N)]),
    "as documented at the first pass: the whole string one big-endian integer":
        lambda rng, N: int.from_bytes(b"".join(rng.next_bytes(8) for _ in range(N)), "big"),
    "draw i is limb i, little-endian within the limb":
        lambda rng, N: M.from_limbs([int.from_bytes(rng.next_bytes(8), "little") for _ in range(N)]),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runner", required=True)
    ap.add_argument("--seed", type=int, default=20261122)
    a = ap.parse_args()
    stream = random.Random(a.seed).randbytes(1 << 20)
    case = f"1 keygen HALF=16 rounds=5 strength=256 required=112 stream={stream.hex()}\n"
    out = subprocess.run([a.runner], input=case.encode(), capture_output=True).stdout.decode().split()
    if out[:2] != ["1", "OK"]:
        print("the crate's key generation did not return a key:", " ".join(out)[:200])
        print("LIMB ORDER CHECK FAILED")
        return 1
    rust = {"n": int(out[2], 16), "p": int(out[5], 16), "q": int(out[6], 16), "consumed": int(out[10])}
    print(f"crate: RSA-2048 key from a {len(stream)}-byte stream, {rust['consumed']} bytes consumed, p = {out[5][:16]}...")
    original, verdicts = M.fill_random, []
    try:
        for name, reading in READINGS.items():
            M.fill_random = reading
            rng = M.StreamRng(stream)
            try:
                _pk, sk = M.keygen_from_rng(rng, 5, 112, 16)
                same = (sk.p, sk.q, rng.pos) == (rust["p"], rust["q"], rust["consumed"])
                detail = f"p = {sk.p:0256x}"[:20] + f"..., {rng.pos} bytes consumed"
            except M.ModelError as err:
                same, detail = False, f"no key ({err.kind})"
            verdicts.append(same)
            print(f"model, {name}: {'the same key' if same else 'another key'} ({detail})")
    finally:
        M.fill_random = original
    ok = verdicts == [True, False, False]
    print("LIMB ORDER CHECK PASSED: the key is the documented reading's and no other's" if ok else "LIMB ORDER CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
