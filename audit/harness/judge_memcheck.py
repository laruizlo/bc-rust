#!/usr/bin/env python3
"""Reads one memcheck log of ct_memcheck and gives the mode's verdict.

    judge_memcheck.py <kind> <log> <crypto dir> <register>     kind: kernel | whole

Prints `verdict<TAB>detail`. Verdicts:
  VOID          the control scan over the mode's own tainted values was not reported: the
                inputs were not undefined, and silence would prove nothing
  clean         only the control scan was reported
  reported      something else was, in the audited code or the harness: detail lists where
  declassified  (whole operations) everything else reported is a line of the declassification
                register whose argument is written: detail lists the entries met
  open          as declassified, but an entry met is still open: detail lists them
  result-handling
                (whole operations) there are reports outside the register, and none of them
                has a frame in the arithmetic, the mask generation or the decoding: all lie in
                what `rsaes_oaep.rs` does with a decryption's result once `decode_out` has
                returned it. Detail lists them. Not a clean bill: the list is what plan gap
                G16 has to argue. It is the statement that nothing before that point is seen.
A report is a register entry's when the entry's line is a frame of it and every frame inside
that one lies in the entry's `via` files (helpers inlined into the line). Line numbers are
looked up from the entries' anchor text at run time.
"""
import os
import re
import sys

FRAME = re.compile(r"^==\d+==\s+(?:at|by) 0x[0-9A-Fa-f]+: (.*) \((.*)\)\s*$")
HEAD = re.compile(r"^==\d+== (Conditional jump or move depends on uninitialised value|"
                  r"Use of uninitialised value|Syscall param .* uninitialised|Invalid |Process terminating)")


def reports(path):
    out, cur = [], None
    for line in open(path, errors="replace"):
        if HEAD.match(line):
            cur = {"what": line.split("== ", 1)[1].strip(), "frames": []}
            out.append(cur)
            continue
        m = FRAME.match(line)
        if m and cur is not None:
            where = m.group(2)
            if where.startswith("in "):
                file, lineno = where, None
            else:
                file, _, lineno = where.rpartition(":")
                lineno = int(lineno) if lineno.isdigit() else None
            cur["frames"].append((m.group(1), file, lineno))
        elif cur is not None and not m and re.match(r"^==\d+==\s*$", line):
            cur = None
    return out


def register(path, crypto):
    entries = []
    for raw in open(path):
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        ident, status, file, anchor, via, reason = [f.strip() for f in raw.split(" | ", 5)]
        src = open(os.path.join(crypto, file)).read().splitlines()
        hits = [i + 1 for i, text in enumerate(src) if anchor in text]
        if len(hits) != 1:
            sys.exit(f"register entry {ident}: anchor found {len(hits)} times in {file}; the source moved")
        entries.append({"id": ident, "status": status, "base": os.path.basename(file), "line": hits[0],
                        "via": {os.path.basename(v) for v in via.split(",") if v}, "reason": reason})
    return entries


def covered_by(rep, entries):
    for e in entries:
        for j, (_fn, file, lineno) in enumerate(rep["frames"]):
            if os.path.basename(file) == e["base"] and lineno == e["line"]:
                if all(os.path.basename(f) in e["via"] for _n, f, _l in rep["frames"][:j]):
                    return e
                break
    return None


def _name(fn):
    return re.sub(r"<.*", "", fn).split("::")[-1]


def _outside(file):
    """A frame of the C library, of Valgrind's replacements or of the Rust standard library."""
    return file.startswith("in ") or "library/" in file or "/rustc/" in file


def site(rep):
    """The innermost frame; and, when that frame is outside the workspace (a `memmove` whose
    source address was selected by a secret is reported inside `memmove`), the first frame
    that is in it. The form of a leak depends on the compiler: observation O1."""
    if not rep["frames"]:
        return "? (?)"
    fn, file, lineno = rep["frames"][0]
    text = f"{_name(fn)} ({os.path.basename(file)}:{lineno})"
    if _outside(file):
        for fn2, file2, line2 in rep["frames"][1:]:
            if not _outside(file2):
                return f"{text} under {_name(fn2)} ({os.path.basename(file2)}:{line2})"
    return text


def main():
    kind, log, crypto, reg = sys.argv[1:5]
    reps = reports(log)
    is_control = lambda r: bool(r["frames"]) and "control" in r["frames"][0][0] and "ct_memcheck" in r["frames"][0][1]
    control = [r for r in reps if is_control(r)]
    others = [r for r in reps if not is_control(r)]
    if not control:
        print("VOID\tthe control scan was not reported")
        return
    if not others:
        print("clean\t-")
        return
    entries = register(reg, crypto) if kind == "whole" else []
    met, loose = {}, []
    for r in others:
        e = covered_by(r, entries)
        if e:
            met[e["id"]] = e
        else:
            loose.append(site(r))
    uniq = list(dict.fromkeys(loose))
    if uniq:
        extra = (" | register: " + ",".join(sorted(met))) if met else ""
        verdict = "reported"
        if kind == "whole":
            # every RSA source but rsaes_oaep.rs, and the two limb kernels of `ec`
            silent = {f for f in os.listdir(os.path.join(crypto, "rsa", "src")) if f != "rsaes_oaep.rs"}
            silent |= {"nat.rs", "montgomery.rs"}
            unexplained = [r for r in others if not covered_by(r, entries)]
            if not any(os.path.basename(f) in silent for r in unexplained for _n, f, _l in r["frames"]):
                verdict = "result-handling"
                where = []
                for r in unexplained:                 # the line of rsaes_oaep.rs each report is under
                    at = next((f"rsaes_oaep.rs:{l}" for _n, f, l in r["frames"] if os.path.basename(f) == "rsaes_oaep.rs"), "?")
                    where.append(f"{site(r)} under {at}")
                uniq = list(dict.fromkeys(where))
        print(verdict + "\t" + "; ".join(uniq) + extra)
    else:
        verdict = "open" if any(e["status"] == "open" for e in met.values()) else "declassified"
        print(verdict + "\t" + ", ".join(f"{i} {met[i]['base']}:{met[i]['line']} ({met[i]['status']})" for i in sorted(met)))


if __name__ == "__main__":
    main()
