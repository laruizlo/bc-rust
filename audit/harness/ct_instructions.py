#!/usr/bin/env python3
"""Reads `objdump -d -l -C --no-show-raw-insn` of the harness binary on stdin and lists, for
each selected machine function, every conditional jump, conditional move and setcc with the
source line the line tables attribute it to. Driven by show_ct_instructions.sh, which says how
to read the table.

    ct_instructions.py [-v] [SYMBOL-SUBSTRING ...]

Classes of source line
  ct       a line of the constant-time context chain: pow2_mod_ct, ct_shift_in_bit_mod,
           ct_select_array, for_secret_modulus in modexp.rs; add, sub in nat.rs
  VARTIME  a line of double_mod_n_vartime, pow2_mod_vartime, for_public_modulus
  loop     a line of the standard library's range and slice iterators: a loop counter
  other    anything else, printed as file:line; the audited files' text is shown
"""
import os
import re
import sys

args = sys.argv[1:]
verbose = "-v" in args
chosen = [a for a in args if a != "-v"]
# By default the RSA-2048 instances of the functions that build a context and run the CRT.
# rustc 1.97 writes the const arguments into a symbol (`pow2_mod_ct::<16>`); rustc 1.88's
# symbols have none (`pow2_mod_ct`), so there every instance is listed, told apart by its
# address and its instruction count.
want = chosen or ["pow2_mod_ct", "rsa_core::crt_exp", "for_public_modulus", "for_secret_modulus"]
RSA_2048 = ("<16>", "<32, 64, 65, 16, 32, 33>")


def selected(symbol):
    if not any(w in symbol for w in want):
        return False
    if chosen or "<" not in symbol.replace("<impl", "").replace("<rsa_audit_harness", ""):
        return True
    return any(a in symbol for a in RSA_2048)
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "crypto")
SOURCES = {"modexp.rs": "rsa/src/modexp.rs", "rsa_core.rs": "rsa/src/rsa_core.rs", "nat.rs": "ec/src/nat.rs",
           "montgomery.rs": "ec/src/montgomery.rs", "ct.rs": "utils/src/ct.rs", "secret.rs": "utils/src/secret.rs"}
TEXT = {b: open(os.path.join(root, p)).read().splitlines() for b, p in SOURCES.items()}


def ranges(base, names):
    src, out = TEXT[base], {}
    for name in names:
        for i, line in enumerate(src):
            m = re.match(r"^(\s*)(pub(\([a-z]+\))? )?(const )?fn " + re.escape(name) + r"\b", line)
            if m:
                j = next(k for k in range(i, len(src)) if src[k] == m.group(1) + "}")
                out[name] = (i + 1, j + 1)
                break
        else:
            sys.exit(f"{base}: fn {name} not found; the source moved")
    return out


CT = {"modexp.rs": ranges("modexp.rs", ["pow2_mod_ct", "ct_shift_in_bit_mod", "ct_select_array", "for_secret_modulus"]),
      "nat.rs": ranges("nat.rs", ["add", "sub"])}
VT = {"modexp.rs": ranges("modexp.rs", ["double_mod_n_vartime", "pow2_mod_vartime", "for_public_modulus"])}


def classify(path, line):
    base = path.rsplit("/", 1)[-1]
    for label, table in (("ct", CT), ("VARTIME", VT)):
        for name, (a, z) in table.get(base, {}).items():
            if a <= line <= z:
                return label, name
    if "/library/" in path or path.startswith("library/"):
        if re.search(r"iter/|range\.rs|cmp\.rs|slice/", path):
            return "loop", base
        return "other", "std " + base
    return "other", base


sym, loc = None, None
rows, shown, per_fn = {}, {}, {}
for raw in sys.stdin:
    raw = raw.rstrip("\n")
    m = re.match(r"^([0-9a-f]+) <(.*)>:$", raw)
    if m:
        sym = re.sub(r"::h[0-9a-f]{16}$", "", m.group(2))
        if not re.search(r"<\d", sym):               # no const arguments in the name: add the address
            sym += " @" + m.group(1).lstrip("0")
        continue
    m = re.match(r"^(\S+\.rs):(\d+)( \(discriminator \d+\))?$", raw)
    if m:
        loc = (m.group(1), int(m.group(2)))
        continue
    m = re.match(r"^\s+[0-9a-f]+:\t(\S+)", raw)
    if not m or loc is None or sym is None or not selected(sym):
        continue
    mnem = m.group(1)
    kind = ("jcc" if re.fullmatch(r"j[a-z]+", mnem) and mnem != "jmp" else
            "cmov" if mnem.startswith("cmov") else
            "setcc" if re.fullmatch(r"set[a-z]+", mnem) else None)
    per_fn.setdefault(sym, {"jcc": 0, "cmov": 0, "setcc": 0, "insns": 0})["insns"] += 1
    if kind is None:
        continue
    per_fn[sym][kind] += 1
    label, name = classify(*loc)
    key = (sym, label, name, loc[0].rsplit("/", 1)[-1], loc[1])
    rows.setdefault(key, {"jcc": 0, "cmov": 0, "setcc": 0})[kind] += 1
    shown.setdefault(key, []).append(raw.strip())

order = {"ct": 0, "VARTIME": 1, "loop": 2, "other": 3}
for fn in sorted(per_fn):
    t = per_fn[fn]
    print(f"\n{fn.replace('rsa_audit_harness::', '')}")
    print(f"  {t['insns']} instructions: {t['jcc']} conditional jumps, {t['cmov']} conditional moves, {t['setcc']} setcc")
    print("  %-8s %-22s %-22s %4s %5s %6s  %s" % ("class", "source function", "file:line", "jcc", "cmov", "setcc", "source line"))
    for key in sorted((k for k in rows if k[0] == fn), key=lambda k: (order[k[1]], k[3], k[4])):
        c = rows[key]
        text = TEXT[key[3]][key[4] - 1].strip()[:64] if key[3] in TEXT and key[1] != "loop" else ""
        print("  %-8s %-22.22s %-22s %4d %5d %6d  %s" % (key[1], key[2], f"{key[3]}:{key[4]}", c["jcc"], c["cmov"], c["setcc"], text))
        if verbose:
            for ins in shown[key]:
                print("          " + ins)
if not per_fn:
    print("(no machine function matches: " + ", ".join(want) + ")")
