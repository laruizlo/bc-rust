#!/usr/bin/env python3
"""Generate known-answer vectors for the bouncycastle-rsa bigint layer.

Writes crypto/rsa/tests/bigint/vectors_data.rs: committed, deterministic,
derived from SHA-256 of fixed tag strings (no RNG state, no timestamps), with
expected values computed by Python's unbounded integers as the independent
oracle. Run from the repo root:

    python3 dev_scripts/gen_bigint_vectors.py

Regenerating must produce a byte-identical file; CI or reviewers can diff.
"""

import hashlib
import os

OUT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "crypto", "rsa", "tests", "bigint", "vectors_data.rs"
)

N_RANDOM = 10  # pseudorandom cases per operation, on top of the boundary grid
BE_CASES = 6  # random 32-byte encoding cases
RAGGED_LENS = [0, 1, 2, 5, 31, 32]  # ragged-slice lengths (<= 32-byte capacity)


def words_from_tag(tag: str, count: int, width: int) -> list[int]:
    """Deterministic words: sha256(tag-i), big-endian truncation to width bits."""
    out = []
    for i in range(count):
        digest = hashlib.sha256(f"bigint-vec-{tag}-{i}".encode()).digest()
        out.append(int.from_bytes(digest[: width // 8], "big"))
    return out


def bytes_from_tag(tag: str, i: int, length: int) -> bytes:
    """Deterministic byte string of the given length (sha256 stream)."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"bigint-vec-{tag}-{i}-{counter}".encode()).digest()
        counter += 1
    return out[:length]


def boundary(width: int) -> list[int]:
    m = (1 << width) - 1
    return [0, 1, m, m - 1, 1 << (width - 1)]


def hexw(v: int, width: int) -> str:
    return f"0x{v:0{width // 4}x}"


def gen_adc(width: int) -> list[tuple[int, ...]]:
    m = (1 << width) - 1
    cases = []
    for a in boundary(width):
        for b in boundary(width):
            for c in (0, 1):
                s = a + b + c
                cases.append((a, b, c, s & m, s >> width))
    rand = words_from_tag(f"adc{width}", 2 * N_RANDOM, width)
    for i in range(N_RANDOM):
        a, b, c = rand[2 * i], rand[2 * i + 1], i & 1
        s = a + b + c
        cases.append((a, b, c, s & m, s >> width))
    return cases


def gen_sbb(width: int) -> list[tuple[int, ...]]:
    m = (1 << width) - 1
    cases = []
    for a in boundary(width):
        for b in boundary(width):
            for borrow_in in (0, m):
                bin_bit = borrow_in >> (width - 1)
                d = (a - b - bin_bit) & m
                borrow_out = m if a < b + bin_bit else 0
                cases.append((a, b, borrow_in, d, borrow_out))
    rand = words_from_tag(f"sbb{width}", 2 * N_RANDOM, width)
    for i in range(N_RANDOM):
        a, b = rand[2 * i], rand[2 * i + 1]
        borrow_in = m if i & 1 else 0
        bin_bit = borrow_in >> (width - 1)
        d = (a - b - bin_bit) & m
        borrow_out = m if a < b + bin_bit else 0
        cases.append((a, b, borrow_in, d, borrow_out))
    return cases


def gen_mac(width: int) -> list[tuple[int, ...]]:
    m = (1 << width) - 1
    cases = []
    for b in boundary(width):
        for c in boundary(width):
            t = b * c
            cases.append((0, b, c, 0, t & m, t >> width))
    rand = words_from_tag(f"mac{width}", 4 * N_RANDOM, width)
    for i in range(N_RANDOM):
        acc, b, c, carry = rand[4 * i], rand[4 * i + 1], rand[4 * i + 2], rand[4 * i + 3]
        t = acc + b * c + carry
        cases.append((acc, b, c, carry, t & m, t >> width))
    return cases


def limbs_of(value: int, width: int, count: int) -> list[int]:
    m = (1 << width) - 1
    return [(value >> (width * i)) & m for i in range(count)]


def rust_tuple(values: tuple[int, ...], width: int) -> str:
    return "(" + ", ".join(hexw(v, width) for v in values) + ")"


def emit_width(width: int) -> str:
    word = f"u{width}"
    limb_count = 256 // width
    lines = []
    lines.append(f"    pub const ADC: &[({word}, {word}, {word}, {word}, {word})] = &[")
    for case in gen_adc(width):
        lines.append(f"        {rust_tuple(case, width)},")
    lines.append("    ];")
    lines.append(f"    pub const SBB: &[({word}, {word}, {word}, {word}, {word})] = &[")
    for case in gen_sbb(width):
        lines.append(f"        {rust_tuple(case, width)},")
    lines.append("    ];")
    lines.append(f"    pub const MAC: &[({word}, {word}, {word}, {word}, {word}, {word})] = &[")
    for case in gen_mac(width):
        lines.append(f"        {rust_tuple(case, width)},")
    lines.append("    ];")

    lines.append(f"    pub const BE256: &[([u8; 32], [{word}; {limb_count}])] = &[")
    for i in range(BE_CASES):
        raw = bytes_from_tag("be256", i, 32)
        value = int.from_bytes(raw, "big")
        byte_list = ", ".join(str(b) for b in raw)
        limb_list = ", ".join(hexw(l, width) for l in limbs_of(value, width, limb_count))
        lines.append(f"        ([{byte_list}], [{limb_list}]),")
    lines.append("    ];")

    lines.append(f"    pub const RAGGED: &[(&[u8], [{word}; {limb_count}])] = &[")
    for i, length in enumerate(RAGGED_LENS):
        raw = bytes_from_tag("ragged", i, length)
        if i == 1:
            raw = b"\x00" * max(0, length)  # explicit leading-zero/empty-ish case
        value = int.from_bytes(raw, "big") if raw else 0
        byte_list = ", ".join(str(b) for b in raw)
        limb_list = ", ".join(hexw(l, width) for l in limbs_of(value, width, limb_count))
        lines.append(f"        (&[{byte_list}], [{limb_list}]),")
    lines.append("    ];")
    return "\n".join(lines)


def main() -> None:
    parts = []
    parts.append("// GENERATED by dev_scripts/gen_bigint_vectors.py. Do not edit by hand.")
    parts.append("// Regenerate with: python3 dev_scripts/gen_bigint_vectors.py")
    parts.append("// Values derive from SHA-256 of fixed tags; regeneration is byte-identical.")
    parts.append("")
    parts.append('#[cfg(all(target_pointer_width = "64", not(force_limb32)))]')
    parts.append("mod data {")
    parts.append(emit_width(64))
    parts.append("}")
    parts.append("")
    parts.append('#[cfg(any(not(target_pointer_width = "64"), force_limb32))]')
    parts.append("mod data {")
    parts.append(emit_width(32))
    parts.append("}")
    parts.append("")

    with open(OUT_PATH, "w") as f:
        f.write("\n".join(parts))
    print(f"wrote {os.path.normpath(OUT_PATH)}")


if __name__ == "__main__":
    main()
