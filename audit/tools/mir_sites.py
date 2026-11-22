#!/usr/bin/env python3
"""Where a key value is built, as the compiler lists it (plan I1; finding F-02, row (e)).

    python3 -I audit/tools/mir_sites.py [--root <bc-rust checkout>] [--target-dir <dir>] [--no-control]

The proof of I1 starts from a list: every place in the crate where a value of one of the six
key types is constructed. `listed_searches.py i1` reads that list off the source text, form by
form. This tool reads it off what the compiler made of the source.

`rustc --emit=mir` (stable) writes the crate's MIR, the form every function body has after
macro expansion, name resolution and type checking. There the construction of a struct value
is one statement, an aggregate, whatever the source wrote -- braces, a constructor call, an
alias, `Self`, an associated type, a derive's expansion:

    _0 = RsaPublicComponents::<K> { n: move _2, e: copy _3 };
    _0 = RsaKEMPublicKey::<K>(move _1);

A tuple struct's constructor passed as a function is its path with nothing built at that
place; the constructor's own body is then the aggregate. The dev profile is used: without
optimisation MIR bodies are not inlined into one another, so an aggregate stands in the
function that wrote it.

The same file answers the proof's third step, that no key changes after it is built: a
change is an assignment to a place inside the key or a mutable borrow of one, and MIR writes
places with their types -- `(_40.0: Secret<..>)` is field 0 of local 40, whose declaration
says it is a key.

What is printed: every aggregate of a key type with the body it stands in; every other
mention of a key type's value path; every statement that assigns to a place inside a key or
borrows one mutably. What is checked: the aggregates are MIR_SITES below, no constructor is
used as a function value, and the writes are MIR_WRITES. Exit 1 on a deviation.

Control: the same reading on copies of the workspace with one edit each (MIR_EDITS), each a
way of writing a key, or of changing one, that compiles. Every edit must be reported.

What this does not show: that rustc's MIR names every aggregate the program builds. That is
a property of the compiler, relied on; the control shows it for the forms tried.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

SIX = ("RsaPublicComponents", "RsaPrivateComponents", "RsaPublicKey", "RsaPrivateKey",
       "RsaKEMPublicKey", "RsaKEMPrivateKey")
# (type, module, function, kind). kind: written -- the source has the expression; derived --
# the body is a derive's (`#[derive(Clone)]`: a copy, field by field); constructor -- the body
# of a tuple struct's own constructor function, which runs only where something passes the
# constructor as a function, and nothing does.
MIR_SITES = {
    ("RsaPublicComponents", "keys", "new", "written"),
    ("RsaPublicComponents", "keys", "clone", "derived"),
    ("RsaPrivateComponents", "keys", "clone_in_own_frame", "written"),
    ("RsaPrivateComponents", "keys", "validated", "written"),
    ("RsaPublicKey", "keys", "from_components", "written"),
    ("RsaPublicKey", "keys", "clone", "written"),
    ("RsaPrivateKey", "keys", "key", "written"),
    ("RsaPrivateKey", "keys", "from_components", "written"),
    ("RsaPrivateKey", "keys", "clone", "written"),
    ("RsaKEMPublicKey", "rsasve", "from_rsa_key", "written"),
    ("RsaKEMPublicKey", "rsasve", "clone", "derived"),
    ("RsaKEMPublicKey", "-", "RsaKEMPublicKey", "constructor"),
    ("RsaKEMPrivateKey", "rsasve", "from_rsa_key", "written"),
    ("RsaKEMPrivateKey", "rsasve", "clone", "derived"),
    ("RsaKEMPrivateKey", "-", "RsaKEMPrivateKey", "constructor"),
}
# The bodies in which a place inside a key is assigned or borrowed mutably: (type, module,
# function). One: `validated` fills the five secrets of the key it has just built.
MIR_WRITES = {("RsaPrivateComponents", "keys", "validated")}
# One edit each, to a copy of the workspace: ways of writing a key, and of changing one, that
# compile. (file, old, new)
DEAD = "#[allow(dead_code)]\n"
MIR_EDITS = (
    ("a constructor that skips the checks", "keys.rs", "impl<K: RsaSize> RsaPublicComponents<K> {",
     "impl<K: RsaSize> RsaPublicComponents<K> {\n    " + DEAD + "    fn unchecked(n: &K::Limbs, e: u64) -> Self {\n        Self { n: *n, e }\n    }\n"),
    ("a struct expression with generic arguments", "keys.rs", "impl<K: RsaSize> RsaPublicComponents<K> {",
     "impl<K: RsaSize> RsaPublicComponents<K> {\n    " + DEAD + "    fn unchecked_e(n: &K::Limbs, e: u64) -> u64 {\n        let key = RsaPublicComponents::<K> { n: *n, e };\n        key.e\n    }\n"),
    ("a tuple constructor outside from_rsa_key", "rsasve_kdf.rs", "const fn len_check<",
     DEAD + "fn forged<K: RsaSize>(pk: crate::keys::RsaPublicComponents<K>) -> bool {\n    RsaKEMPublicKey(pk).e() == 3\n}\n\nconst fn len_check<"),
    ("a tuple constructor passed as a function", "rsasve_kdf.rs", "const fn len_check<",
     DEAD + "fn forged<K: RsaSize>(pk: Option<crate::keys::RsaPublicComponents<K>>) -> bool {\n    pk.map(RsaKEMPublicKey).is_some()\n}\n\nconst fn len_check<"),
    ("a tuple key written with braces", "rsasve_kdf.rs", "const fn len_check<",
     DEAD + "fn forged<K: RsaSize>(pk: crate::keys::RsaPublicComponents<K>) -> bool {\n    let key = RsaKEMPublicKey { 0: pk };\n    key.e() == 3\n}\n\nconst fn len_check<"),
    ("a key written through an alias", "rsa_2048.rs", "/// Length of an RSASVE-2048 ciphertext",
     DEAD + "fn forged(pk: crate::keys::RsaPublicComponents<RSA2048>) -> bool {\n    let key = RSA2048KEMPublicKey { 0: pk };\n    key.e() == 3\n}\n\n/// Length of an RSASVE-2048 ciphertext"),
    ("a key written through an associated type of the impl", "size.rs",
     "        keygen_as::<K, _, _>(rng, crate::rsasve::keygen_from::<K>)\n",
     "        let _forge = |pk: RsaPublicComponents<K>| Self::PublicKey { 0: pk };\n        keygen_as::<K, _, _>(rng, crate::rsasve::keygen_from::<K>)\n"),
    ("a field of a key assigned", "keys.rs", "impl<K: RsaSize> RsaPublicComponents<K> {",
     "impl<K: RsaSize> RsaPublicComponents<K> {\n    " + DEAD + "    fn with_e(mut self, e: u64) -> Self {\n        self.e = e;\n        self\n    }\n"),
    ("a limb of a key's modulus changed through an index", "keys.rs", "impl<K: RsaSize> RsaPublicComponents<K> {",
     "impl<K: RsaSize> RsaPublicComponents<K> {\n    " + DEAD + "    fn clear_low_bit(&mut self) {\n        self.n.as_mut()[0] &= !1;\n    }\n"),
    ("the components of a KEM key replaced", "rsasve_kdf.rs", "const fn len_check<",
     DEAD + "fn swap_in<K: RsaSize>(key: &mut RsaKEMPublicKey<K>, other: crate::keys::RsaPublicComponents<K>) {\n    key.0 = other;\n}\n\nconst fn len_check<"),
    ("a key written through an associated type of a parameter", "rsasve_kdf.rs", "const fn len_check<",
     DEAD + "fn forged<K>(pk: crate::keys::RsaPublicComponents<K>) -> bool\nwhere\n    K: RsaSigningSize + crate::size::KemKeyPair<PublicKey = RsaKEMPublicKey<K>>,\n{\n    let key = K::PublicKey { 0: pk };\n    key.e() == 3\n}\n\nconst fn len_check<"),
)
RSA = "crypto/rsa/src"


def build_mir(root, target, out):
    """The crate's MIR, dev profile, written to `out`. Returns cargo's stderr on failure."""
    r = subprocess.run(["cargo", "rustc", "--quiet", "-p", "bouncycastle-rsa", "--lib", "--", f"--emit=mir={out}"],
                       cwd=root, env=dict(os.environ, CARGO_TARGET_DIR=target), capture_output=True, text=True)
    return None if r.returncode == 0 and os.path.exists(out) else (r.stderr or "no MIR written")[-1500:]


def close_angle(s, i):
    """Index after the `>` that closes the `<` at s[i]; `->` does not close anything."""
    depth = 0
    while i < len(s):
        if s[i] == "<":
            depth += 1
        elif s[i] == ">" and s[i - 1] != "-":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(s)


def body_of(header, root):
    """(module, function, kind) of a MIR body from its first line: `fn <path>(..) -> .. {`,
    `const <path>: T = {`, `static <path>: T = {` or `promoted[N] in <path>: T = {`."""
    kind = "written"
    m = re.search(r"<impl at ([^:>]+):(\d+):\d+: \d+:\d+>", header)
    if m:                                    # a derive's impl is located at the derive attribute
        try:
            line = open(os.path.join(root, m.group(1))).read().split("\n")[int(m.group(2)) - 1]
            if "derive(" in line:
                kind = "derived"
        except (OSError, IndexError):
            kind = "written (impl line not read)"
    flat = re.sub(r"<impl at [^>]*>", "<impl>", header)
    flat = re.sub(r"^(fn|const|static mut|static|promoted\[\d+\] in) ", "", flat)
    path = re.split(r"\(|: ", flat, maxsplit=1)[0]
    segs = [x for x in path.split("::") if x and x != "<impl>"]
    module, fn = (segs[0], "::".join(segs[1:])) if len(segs) > 1 else ("-", segs[0] if segs else "?")
    if module == "-" and fn in SIX:
        kind = "constructor"
    return module, fn, kind


KEY_TYPE = re.compile(r"^(?P<ref>(?:&(?:'[a-z_0-9]+ )?(?:mut )?|\*(?:const|mut) )*)(?:[A-Za-z_0-9]+::)*(?P<ty>" + "|".join(SIX) + r")<")
FIELD_OF_LOCAL = re.compile(r"\((?:_(\d+)|\(\*_(\d+)\))\.(\d+): ")
FIELD_OF_FIELD = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(SIX) + r")<")


def key_fields(line, locals_):
    """Start offsets of the places in a MIR line that are a field of a key: `(_N.k: T)` or
    `((*_N).k: T)` with _N a key (or a reference to one), and `(<place>: Key<..>).k`."""
    out = []
    for m in FIELD_OF_LOCAL.finditer(line):
        n = m.group(1) or m.group(2)
        t = KEY_TYPE.match(locals_.get(n, ""))
        if t and bool(t.group("ref")) == (m.group(2) is not None):
            out.append((m.start(), t.group("ty")))
    for m in FIELD_OF_FIELD.finditer(line):
        end = close_angle(line, m.end() - 1)
        if re.match(r"\)\.\d+: ", line[end:]):                 # ..: Key<..>).k: T) -- a field of that key
            start = line.rfind("(", 0, m.start())
            out.append((start, m.group(1)))
    return out


def read_mir(path, root):
    """From a MIR file: the aggregates of the key types; loose mentions of their constructors;
    and the statements that assign to, or borrow mutably, a place inside a key."""
    name = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(SIX) + r")::<")
    sites, loose, writes, paths, bodies = [], [], [], 0, 0
    body, locals_ = None, {}
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if line and not line[0].isspace() and not line.startswith(("}", "//")):
            body = body_of(line, root)
            bodies += 1
            locals_ = {}
            args = list(re.finditer(r"(?<![A-Za-z0-9_])_(\d+): ", line))
            for k, m in enumerate(args):                           # the arguments, from the header
                stop = args[k + 1].start() - 2 if k + 1 < len(args) else line.rfind(") ->")
                locals_[m.group(1)] = line[m.end():stop if stop > 0 else len(line)]
            if " -> " in line:
                locals_["0"] = line[line.rfind(") -> ") + 5:].rstrip(" {")
            continue
        m = re.match(r"\s+let (?:mut )?_(\d+): (.*);$", line)
        if m:
            locals_[m.group(1)] = m.group(2)
            continue
        for m in name.finditer(line):
            end = close_angle(line, m.end() - 1)
            rest = line[end:]
            if rest.startswith("::"):
                paths += 1
            elif rest.startswith(" {") or rest.startswith("("):
                sites.append((m.group(1),) + (body or ("?", "?", "?")))
                if "-> [return" in line:
                    loose.append(f"{m.group(1)}: called as a function in {body}")
            else:
                loose.append(f"{m.group(1)}: the constructor as a value in {body}: {line.strip()[:110]}")
        eq = line.find(" = ")
        for start, ty in key_fields(line, locals_):
            borrowed = re.search(r"&(?:raw )?mut $", line[:start]) is not None
            assigned = eq > 0 and start < eq
            if borrowed or assigned:
                writes.append((ty,) + (body or ("?", "?", "?"))[:2] + ("borrowed mutably" if borrowed else "assigned",))
    return sites, loose, writes, paths, bodies


def report(root, mir, quiet=False):
    sites, loose, writes, paths, bodies = read_mir(mir, root)
    found = set(sites)
    devs = [f"an aggregate the table does not name: {x}" for x in sorted(found - MIR_SITES)]
    devs += [f"in the table, not in the MIR: {x}" for x in sorted(MIR_SITES - found)]
    devs += loose
    wrote = {w[:3] for w in writes}
    devs += [f"a place inside a key is written where the table names none: {x}" for x in sorted(wrote - MIR_WRITES)]
    devs += [f"a write the table names is not in the MIR: {x}" for x in sorted(MIR_WRITES - wrote)]
    if not quiet:
        print(f"   {bodies} MIR bodies; aggregates of a key type: {len(sites)} statements in {len(found)} functions")
        for ty, module, fn, kind in sorted(found):
            n = sites.count((ty, module, fn, kind))
            print(f"   {ty:21s} in {module}::{fn:22s} {kind}" + (f"   ({n} statements)" if n > 1 else ""))
        print(f"   other value paths of a key type (`Type::<..>::function`): {paths}; a constructor used as a function value: {len(loose)}")
        print(f"   places inside a key that are assigned or borrowed mutably: {len(writes)} statements in {len(wrote)} function{'' if len(wrote) == 1 else 's'}")
        for ty, module, fn in sorted(wrote):
            kinds = sorted({w[3] for w in writes if w[:3] == (ty, module, fn)})
            print(f"   {ty:21s} in {module}::{fn:22s} {len([w for w in writes if w[:3] == (ty, module, fn)])} fields {', '.join(kinds)}")
        for d in devs:
            print(f"   DEVIATION: {d}")
    return devs


def shadow(root, tmp):
    """A copy of the workspace without the audit tree and build output."""
    for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml"):
        if os.path.exists(os.path.join(root, name)):
            shutil.copy2(os.path.join(root, name), os.path.join(tmp, name))
    for name in ("src", "cli", "crypto", "mem_usage_benches"):
        shutil.copytree(os.path.join(root, name), os.path.join(tmp, name), ignore=shutil.ignore_patterns("target"))


def control(root, target):
    print("\n=== control: the same reading on copies of the workspace with one edit each")
    missed = 0
    with tempfile.TemporaryDirectory() as tmp:
        shadow(root, tmp)
        out = os.path.join(tmp, "rsa.mir")
        err = build_mir(tmp, target, out)
        base = report(tmp, out, quiet=True) if err is None else [err]
        print("   the copy, unedited: " + ("as the table" if not base else f"DEVIATES: {base[0][:200]}"))
        missed += bool(base)
        for what, name, old, new in MIR_EDITS:
            path = os.path.join(tmp, RSA, name)
            original = open(path).read()
            if old not in original:
                print(f"   {what}: THE EDIT DOES NOT APPLY ({name})")
                missed += 1
                continue
            open(path, "w").write(original.replace(old, new, 1))
            if os.path.exists(out):
                os.remove(out)
            err = build_mir(tmp, target, out)
            open(path, "w").write(original)
            if err is not None:
                first = next((l for l in err.splitlines() if l.startswith("error")), err.strip().splitlines()[-1] if err.strip() else "?")
                print(f"   {what}: THE EDITED COPY DOES NOT BUILD: {first[:150]}")
                missed += 1
                continue
            devs = report(tmp, out, quiet=True)
            print(f"   {what}: " + (f"reported ({len(devs)}): {devs[0][:150]}" if devs else "NOT REPORTED"))
            missed += not devs
    print(f"control: {len(MIR_EDITS) - missed} of {len(MIR_EDITS)} edits reported" + ("" if not missed else "  <-- FAILED"))
    return missed == 0


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.normpath(os.path.join(here, "..", "..")))
    ap.add_argument("--target-dir", help="cargo target directory for these builds (default: $CARGO_TARGET_DIR/mir-sites, or audit/harness/target/mir-sites)")
    ap.add_argument("--no-control", action="store_true")
    a = ap.parse_args()
    root = os.path.abspath(a.root)
    target = a.target_dir or os.path.join(os.environ.get("CARGO_TARGET_DIR") or os.path.join(root, "audit", "harness", "target"), "mir-sites")
    target = os.path.abspath(target)
    os.makedirs(target, exist_ok=True)
    v = subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.strip()
    print(f"\n=== I1: where a key value is built, from the crate's MIR ({v}, dev profile)")
    # A name of this run's own: the output path is part of the compiler's command line, so
    # cargo runs rustc again and the file read below is the one this run wrote.
    out = os.path.join(target, f"bouncycastle_rsa.{os.getpid()}.mir")
    err = build_mir(root, os.path.join(target, "checkout"), out)
    if err is not None:
        print("   THE CRATE'S MIR WAS NOT WRITTEN:\n" + err)
        print("\nMIR SITES: FAILED")
        return 1
    devs = report(root, out)
    os.remove(out)
    ok = not devs
    print("\nMIR SITES: " + ("AS STATED" if ok else f"{len(devs)} DEVIATION(S)"))
    if not a.no_control:
        ok &= control(root, os.path.join(target, "copies"))
    tail = "THE COMPILER'S LIST IS THE TABLE'S" + (" (the control was not run)" if a.no_control else ", EVERY CONTROL EDIT REPORTED")
    print("\nMIR SITES: " + (tail if ok else "DEVIATIONS FOUND"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
