#!/usr/bin/env python3
"""Listed searches over the source at the pin: the syntactic premises of three rows of plan
WP14.4, printed with their lines and checked against what the audit's documents state.

    python3 -I audit/tools/listed_searches.py [i1|roles|m10|all] [--root <bc-rust checkout>]

  i1     finding F-02, row (e); obligation I1 ("no path builds a key around the constructors").
         Every mention of one of the six key types, classified by the form it is written in:
         so where a value is constructed (`mir_sites.py` reads the same list off the
         compiler's MIR); whether a field can be written from outside its module; which
         traits a key type implements; which functions return a key; that nothing takes a
         key by `&mut`; that the size traits are sealed, the crate forbids `unsafe`, and no
         macro of the crate's or of a dependency writes code the text does not show.
  roles  finding F-04, row (b). Every impl of an encapsulating, key-transporting,
         decapsulating, decrypting, signing or verifying role, with its bound on the size; and
         every call of the two raw primitives with the bound it sits under.
  m10    finding F-06, row (b); obligation M10. Every function with const generic parameters
         in the crate and in `ec::{montgomery, barrett}`: whether it is public, the relation
         between its widths, and where that relation is asserted; the literal widths of the
         crate's own routing table, checked numerically.

A search prints what it found and ends with one verdict line. It fails (exit 1) when the
source no longer has the shape the documents describe: a construction site, a returning
function, a role impl or a public generic function that the tables below do not name. The
tables are the audit's statement; the search is what makes it re-runnable. What a search
cannot do is say that it looked for the right thing: that argument is in the proof book
(I1) and in the WP14 report, part 2.

Each run ends with a control: the searches are run again on copies of the source with one
edit each (a constructor that skips the checks, a role impl at every size, a width check
removed, and so on), and every edit must be reported. A search that cannot fail proves
nothing.

The reader is `rust_items.py`: tokens and brace matching, no more.
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rust_items as R  # noqa: E402

RSA = "crypto/rsa/src"
SIX = ("RsaPublicComponents", "RsaPrivateComponents", "RsaPublicKey", "RsaPrivateKey",
       "RsaKEMPublicKey", "RsaKEMPrivateKey")
TUPLE = ("RsaKEMPublicKey", "RsaKEMPrivateKey")


class Src:
    def __init__(self, root, rel):
        self.rel, self.name = rel, os.path.basename(rel)
        self.text = open(os.path.join(root, rel)).read()
        self.toks, self.items = R.scan(self.text)

    def fn_at(self, idx):
        return R.enclosing(self.items, idx, ("fn",))

    def impl_at(self, idx):
        return R.enclosing(self.items, idx, ("impl", "trait"))

    def in_header(self, idx):
        """Whether token idx stands in the header of some item (a signature, an impl line)."""
        return any(it.start <= idx < it.header_end for it in self.items)

    def is_test(self, idx):
        it = R.enclosing(self.items, idx)
        return bool(it and it.test)


def load(root, rels):
    return [Src(root, r) for r in rels]


def rsa_files(root):
    return sorted(f"{RSA}/{f}" for f in os.listdir(os.path.join(root, RSA)) if f.endswith(".rs"))


class Report:
    def __init__(self, title):
        self.bad = []
        print(f"\n=== {title}")

    def section(self, text):
        print(f"\n-- {text}")

    def line(self, text):
        print("   " + text)

    def expect(self, cond, what):
        if not cond:
            self.bad.append(what)
            print(f"   DEVIATION: {what}")

    def same(self, found, expected, what):
        found, expected = set(found), set(expected)
        for x in sorted(found - expected):
            self.expect(False, f"{what}: found but not in the audit's table: {x}")
        for x in sorted(expected - found):
            self.expect(False, f"{what}: in the audit's table but not found: {x}")

    def verdict(self, name):
        print(f"\n{name}: " + ("AS STATED" if not self.bad else f"{len(self.bad)} DEVIATION(S)"))
        return not self.bad


# ====================================================================================== i1
# Where a value of each key type is made, in code that is not a test: (type, function).
I1_SITES = {
    ("RsaPublicComponents", "new"),
    ("RsaPrivateComponents", "clone_in_own_frame"), ("RsaPrivateComponents", "validated"),
    ("RsaPublicKey", "from_components"), ("RsaPublicKey", "clone"),
    ("RsaPrivateKey", "key"), ("RsaPrivateKey", "from_components"), ("RsaPrivateKey", "clone"),
    ("RsaKEMPublicKey", "from_rsa_key"), ("RsaKEMPrivateKey", "from_rsa_key"),
}
# Every function that returns a key or hands one to a closure: file, self type or trait, name.
# The proof book (I1) follows each to `RsaPublicComponents::new` or to `validated`.
I1_RETURNING = {
    ("keys.rs", "RsaPublicComponents", "new"), ("keys.rs", "RsaPublicComponents", "from_bytes_raw"),
    ("keys.rs", "RsaPublicComponents", "key"), ("keys.rs", "RsaPublicComponents", "into_key"),
    ("keys.rs", "RsaPrivateComponents", "clone"), ("keys.rs", "RsaPrivateComponents", "clone_in_own_frame"),
    ("keys.rs", "RsaPrivateComponents", "from_crt_components"),
    ("keys.rs", "RsaPrivateComponents", "from_crt_components_as"),
    ("keys.rs", "RsaPrivateComponents", "from_crt_components_in_own_frame"),
    ("keys.rs", "RsaPrivateComponents", "validated"),
    ("keys.rs", "RsaPrivateComponents", "key"), ("keys.rs", "RsaPrivateComponents", "into_key"),
    ("keys.rs", "RsaPrivateComponents", "from_bytes_raw_as"),
    ("keys.rs", "RsaPrivateComponents", "from_bytes_raw_in_own_frame"),
    ("keys.rs", "RsaPrivateComponents", "decoded"),
    ("keys.rs", "RsaPublicKey", "new"), ("keys.rs", "RsaPublicKey", "from_components"),
    ("keys.rs", "RsaPublicKey", "components"), ("keys.rs", "RsaPublicKey", "clone"),
    ("keys.rs", "RsaPublicKey", "from_bytes"),
    ("keys.rs", "RsaPrivateKey", "from_crt_components"), ("keys.rs", "RsaPrivateKey", "from_components"),
    ("keys.rs", "RsaPrivateKey", "components"), ("keys.rs", "RsaPrivateKey", "clone"),
    ("keys.rs", "RsaPrivateKey", "from_bytes"),
    ("rsasve.rs", "RsaKEMPublicKey", "new"), ("rsasve.rs", "RsaKEMPublicKey", "from_rsa_key"),
    ("rsasve.rs", "RsaKEMPublicKey", "from_bytes"),
    ("rsasve.rs", "RsaKEMPrivateKey", "from_crt_components"), ("rsasve.rs", "RsaKEMPrivateKey", "from_rsa_key"),
    ("rsasve.rs", "RsaKEMPrivateKey", "from_bytes"),
    ("rsasve.rs", "RSASVE", "keygen"), ("rsasve.rs", "-", "keygen_from"),
    ("keygen.rs", "-", "keygen_from_rng"), ("keygen.rs", "-", "keygen_in_own_frame"),
    ("keygen.rs", "-", "keygen_as"), ("keygen.rs", "-", "keygen_as_in_own_frame"),
    ("size.rs", "RsaSigningSize", "keygen"),
    ("size.rs", "RSA2048", "keygen"), ("size.rs", "RSA3072", "keygen"),
    ("size.rs", "RSA4096", "keygen"), ("size.rs", "RSA8192", "keygen"),
    ("size.rs", "SignatureKeyPair", "generate_pkcs1_v1_5_signature_key_pair"),
    ("size.rs", "SignatureKeyPair", "generate_pss_signature_key_pair"),
    ("size.rs", "SignatureKeyPair", "generate_pss_signature_key_pair_with"),
    ("size.rs", "K", "generate_pkcs1_v1_5_signature_key_pair"),
    ("size.rs", "K", "generate_pss_signature_key_pair"),
    ("size.rs", "K", "generate_pss_signature_key_pair_with"),
    ("size.rs", "K", "generate_kem_key_pair"),
}
# The traits implemented for a key type, by `impl` or by derive. None of them makes a key from
# nothing: no Default, no ZeroizablePrimitive (whose ZEROED constant would be an all-zero key),
# no From. The three whose methods return a key (Clone, PublicKey, PrivateKey) are in the
# table above.
I1_TRAITS = {
    "RsaPublicComponents": {"Clone", "Debug", "PartialEq", "Eq"},
    "RsaPrivateComponents": {"Clone", "Debug", "PartialEq", "Eq"},
    "RsaPublicKey": {"Clone", "Debug", "PartialEq", "Eq", "Display", "PublicKey", "VerifyingKey", "OneShotVerifyingKey"},
    "RsaPrivateKey": {"Clone", "Debug", "PartialEq", "Eq", "PrivateKey", "SigningKey", "OneShotSigningKey",
                      "DeterministicSigningKey", "DeterministicOneShotSigningKey"},
    "RsaKEMPublicKey": {"Clone", "Debug", "PartialEq", "Eq", "Display", "PublicKey", "EncapsulatingKey",
                        "KeyTransportEncryptingKey"},
    "RsaKEMPrivateKey": {"Clone", "Debug", "PartialEq", "Eq", "PrivateKey", "DecapsulatingKey",
                         "KeyTransportDecryptingKey"},
}
# The module-level aliases of a key type: the per-size names of the KEM keys.
I1_ALIASES = {f"RSA{b}KEM{h}Key": f"RsaKEM{h}Key" for b in (2048, 3072, 4096, 8192) for h in ("Public", "Private")}
# Where a field of a key is assigned: only while `validated` fills the key it is building.
I1_FIELD_WRITES = {("keys.rs", "validated", f) for f in ("p", "q", "d_p", "d_q", "q_inv")}
# associated types bound to a key type: (file, name) -> the key type. `Self::<name> { .. }` in the
# impl that binds one would be a construction.
I1_ASSOC = {("size.rs", "PublicKey"): "RsaKEMPublicKey", ("size.rs", "PrivateKey"): "RsaKEMPrivateKey"}
# what the language itself provides: an attribute, a derive or a macro outside these sets is
# code the source text does not show
BUILTIN_ATTRS = {"allow", "cfg", "derive", "doc", "forbid", "inline", "must_use", "no_std", "should_panic", "test"}
BUILTIN_DERIVES = {"Clone", "Copy", "Debug", "Default", "Eq", "PartialEq"}
CORE_MACROS = {"assert", "assert_eq", "assert_ne", "cfg", "column", "compile_error", "concat", "debug_assert",
               "debug_assert_eq", "debug_assert_ne", "env", "file", "format_args", "include_bytes", "include_str",
               "line", "matches", "module_path", "option_env", "panic", "stringify", "todo", "unimplemented",
               "unreachable", "write", "writeln"}          # not `include!`: it writes code from another file
SEALED_SIZES = {"RSA1024", "RSA1536", "RSA2048", "RSA3072", "RSA4096", "RSA8192"}


ALIASES = {}        # a `type X = <key type>` of the crate: X -> the key type; filled by search_i1
ASSOC = {}          # (file, name) of an associated type bound to a key type -> the key type; likewise


def self_type(src, idx):
    """The self type of the impl around a token, the trait's name inside a trait, or `-`. An
    alias of a key type counts as the key type."""
    it = src.impl_at(idx)
    if it is None:
        return "-"
    if it.kind == "trait":
        return it.name
    ty = R.impl_parts(it)[1] or "-"
    return ALIASES.get(ty, ty)


def search_i1(root):
    rep = Report("I1: no path builds a key around the constructors (finding F-02, row (e))")
    srcs = load(root, rsa_files(root))
    by = {s.name: s for s in srcs}

    rep.section("1. `unsafe` is forbidden in the crate, none is written, and no macro writes code")
    lib = by["lib.rs"]
    m = re.search(r"^#!\[forbid\(unsafe_code\)\]", lib.text, re.M)
    rep.expect(m is not None, "lib.rs has no #![forbid(unsafe_code)]")
    if m:
        rep.line(f"{RSA}/lib.rs:{lib.text.count(chr(10), 0, m.start()) + 1}: #![forbid(unsafe_code)]")
    uses = [(s.name, t.line) for s in srcs for t in s.toks if t == "unsafe"]
    rep.line(f"`unsafe` tokens in {len(srcs)} files (comments and strings apart): {len(uses)}")
    rep.expect(not uses, f"unsafe in {uses}")
    # Code the source text does not show: a macro of the crate's own, an attribute or derive
    # macro of a dependency, a function-like macro that is not core's. The search reads tokens,
    # so each of these would write code it cannot see.
    attrs, derives, macros, rules = set(), set(), set(), []
    for s in srcs:
        t = s.toks
        for i in range(len(t) - 3):
            if t[i] == "#":
                j = i + 2 if t[i + 1] == "!" else i + 1
                if t[j] == "[":
                    attrs.add(str(t[j + 1]))
                    if t[j + 1] == "derive":
                        derives |= {str(x) for x in t[j + 3:R.close_of(t, j + 2)] if x != ","}
            if t[i] == "macro_rules":
                rules.append(f"{s.name}:{t[i].line}")
            if t[i + 1] == "!" and t[i + 2] in ("(", "[", "{") and re.match(r"[A-Za-z_][A-Za-z0-9_]*$", t[i]) and not s.is_test(i):
                macros.add(str(t[i]))
    rep.line(f"attributes: {', '.join(sorted(attrs))}; derives: {', '.join(sorted(derives))}")
    rep.line(f"function-like macros outside tests: {', '.join(sorted(macros))}; `macro_rules!`: {len(rules)}")
    rep.expect(attrs <= BUILTIN_ATTRS, f"an attribute that is not the language's own: {sorted(attrs - BUILTIN_ATTRS)}")
    rep.expect(derives <= BUILTIN_DERIVES, f"a derive that is not the language's own: {sorted(derives - BUILTIN_DERIVES)}")
    rep.expect(macros <= CORE_MACROS, f"a macro that is not core's: {sorted(macros - CORE_MACROS)}")
    rep.expect(not rules, f"the crate defines a macro: {rules}")

    rep.section("2. the six key types: fields and derives")
    for s in srcs:
        for it in s.items:
            if it.kind == "struct" and it.name in SIX and not it.test:
                body = s.toks[it.header_end + 1:it.end] if s.toks[it.header_end] == "{" else it.header
                fields = R.join(body)
                derives = " ".join(a for a in it.attrs if "derive" in a) or "(no derive)"
                rep.line(f"{s.rel}:{it.line}: {it.vis} struct {it.name}  {derives}")
                rep.line(f"      fields: {fields[:150]}")
                rep.expect("Default" not in derives, f"{it.name} derives Default")
                if it.name in TUPLE:
                    rep.expect("pub(crate)" in fields.replace(" ", "") and "pub " not in fields.replace("pub(crate)", ""),
                               f"{it.name}'s field is not pub(crate)")
                else:
                    rep.expect("pub" not in body, f"{it.name} has a field that is not private")
    found = {it.name for s in srcs for it in s.items if it.kind == "struct" and it.name in SIX}
    rep.same(found, SIX, "key type definitions")
    traits = {ty: set() for ty in SIX}
    for s in srcs:
        for it in s.items:
            if it.test:
                continue
            if it.kind == "struct" and it.name in SIX:
                for a in it.attrs:
                    m = re.match(r"#\[derive\((.*)\)\]", a)
                    if m:
                        traits[it.name] |= {x.strip() for x in m.group(1).split(",") if x.strip()}
            if it.kind == "impl":
                tr, ty = R.impl_parts(it)
                if tr is not None and ty in SIX:
                    traits[ty].add(tr)
    for ty in SIX:
        rep.line(f"traits of {ty}: {', '.join(sorted(traits[ty]))}")
        rep.same(traits[ty], I1_TRAITS[ty], f"traits implemented for {ty}")
    # Other names for a key type. A module-level alias is the type as far as a struct expression
    # or an impl goes; an associated type bound to a key type names it inside its impl, and
    # anywhere under an equality bound (`K: Tr<A = Key>`). Every `type X = ..;` of the crate
    # is read, to a fixpoint: an alias of an alias, or of a path that ends in such an
    # associated type, is a name for the key type too.
    ALIASES.clear()
    ASSOC.clear()
    type_items = []                     # (src, token index of `type`, name, right side, in an impl)
    for s in srcs:
        t = s.toks
        for i in range(len(t) - 3):
            if t[i] == "type" and re.match(r"[A-Za-z_]", t[i + 1]) and not s.is_test(i):
                end = next((j for j in range(i, len(t)) if t[j] == ";"), len(t) - 1)
                eq = next((j for j in range(i, end) if t[j] == "="), None)
                owner = s.impl_at(i)
                if eq is not None and (owner is None or owner.kind == "impl"):
                    type_items.append((s, i, str(t[i + 1]), t[eq + 1:end], owner is not None))
    grew = True
    while grew:
        grew = False
        for s, i, name, rhs, in_impl in type_items:
            cut = next((k for k, x in enumerate(rhs) if x in ("<", "where")), len(rhs))
            head = [x for x in rhs[:cut] if re.match(r"[A-Za-z_]", x)]
            target = ALIASES.get(head[-1], head[-1]) if head else None
            if target == "Self":
                target = self_type(s, i)
            via = [ASSOC[k] for k in ASSOC for j, x in enumerate(rhs[:-1]) if x == "::" and rhs[j + 1] == k[1]]
            if target not in SIX and via:
                target = via[0]                      # `type X = <K as Tr>::A`, A bound to a key type
            if target not in SIX:
                continue
            if in_impl and (s.name, name) not in ASSOC:
                ASSOC[(s.name, name)] = target
                grew = True
            elif not in_impl and name not in ALIASES:
                ALIASES[name] = target
                grew = True
    for s, i, name, rhs, in_impl in type_items:
        if not in_impl and name in ALIASES:
            rep.line(f"{s.rel}:{s.toks[i].line}: alias {name} = {ALIASES[name]}<..>")
    rep.same(ALIASES.items(), I1_ALIASES.items(), "aliases of a key type")
    renamed = [(s.name, t.line) for s in srcs for i, t in enumerate(s.toks[:-1]) if t in SIX and s.toks[i + 1] == "as"]
    rep.line(f"`use <key type> as <other name>` in the crate: {len(renamed)}")
    rep.expect(not renamed, f"a key type imported under another name: {renamed}")

    rep.section("3. construction sites: every mention of a key type, by the form it is written in")
    # The forms in which stable Rust writes a value of a struct type (the constructing ones build
    # with rustc 1.97.0 and 1.88.0 and the others do not: compile checks, family `lang`):
    #   `P { .. }`     P the struct's name, with `::<..>` or without; an alias of it; `Self`;
    #                  `Self::A`, A an associated type of the enclosing impl
    #   `P(..)`, `P`   a tuple struct only: its name, with `::<..>` or without, or `Self`, called
    #                  or passed as a function; not an alias, not an associated type
    # and a derive (section 2). So a construction mentions the type by its name, an alias, `Self`
    # inside one of its impls, or an associated type bound to it. Every such mention in the
    # crate is classified here; one that fits no class is a deviation, and so is a constructing
    # form that the table does not name. A pattern has the same form as an expression and is
    # counted as one: the table would have to name it.
    assoc = dict(ASSOC)                          # associated types bound to a key type
    for s, i, name, rhs, in_impl in type_items:
        if in_impl and (s.name, name) in assoc:
            rep.line(f"{s.rel}:{s.toks[i].line}: associated type {name} = {assoc[(s.name, name)]}<..>")
    rep.same(assoc.items(), I1_ASSOC.items(), "associated types bound to a key type")
    assoc_names = {name for (_f, name) in assoc}
    # An equality bound makes `K::A { .. }` a way to write a key wherever the bound holds.
    bounds = []
    for s in srcs:
        t = s.toks
        for i in range(1, len(t) - 2):
            if t[i + 1] == "=" and t[i - 1] in ("<", ",") and re.match(r"[A-Z]", t[i]) and not s.is_test(i):
                head = ALIASES.get(t[i + 2], t[i + 2])
                if head in SIX or (head == "Self" and self_type(s, i) in SIX):
                    bounds.append(f"{s.rel}:{t[i].line}: {t[i]} = {t[i + 2]}")
                    assoc_names.add(str(t[i]))
    rep.line(f"equality bounds that bind an associated type to a key type (`Tr<A = Key>`): {len(bounds)}")
    rep.expect(not bounds, f"an equality bound names a key type: {bounds}")
    use_lines = {}
    for s in srcs:
        spans = set()
        for m in re.finditer(r"^[ \t]*(?:pub(?:\([a-z]+\))? )?use [^;]*;", s.text, re.M):
            first = s.text.count("\n", 0, m.start()) + 1
            spans |= set(range(first, first + m.group(0).count("\n") + 1))
        use_lines[s.name] = spans
    sites, test_sites, classes, loose = set(), 0, {}, []
    for s in srcs:
        t = s.toks
        body_brace = {it.header_end for it in s.items}

        def site(ty, i, form):
            nonlocal test_sites
            if s.is_test(i):
                test_sites += 1
                return
            fn = s.fn_at(i)
            sites.add((ty, fn.name if fn else "?"))
            rep.line(f"{s.rel}:{t[i].line}: {ty} in fn {fn.name if fn else '?'}   [{form}]")

        for i, tok in enumerate(t):
            if i + 2 >= len(t):
                continue
            if tok == "::" and t[i + 1] in assoc_names and t[i + 2] == "{" and (i + 2) not in body_brace:
                bound_to = sorted({v for (_f, n), v in assoc.items() if n == t[i + 1]})
                site(bound_to[0] if bound_to else "a key type", i + 1, "through an associated type")
                continue
            named = ALIASES.get(tok, tok)
            is_self = tok == "Self" and self_type(s, i) in SIX
            if named not in SIX and not is_self:
                continue
            ty = self_type(s, i) if is_self else named
            j = i + 1
            fish = t[j] == "::" and t[j + 1] == "<"
            if fish:
                j = R.angle_close(t, j + 1) + 1
            nxt, prev = t[j], (t[i - 1] if i else "")
            if nxt == "{" and j not in body_brace:
                cls = None
                site(ty, i, "braces")
            elif nxt == "(":
                cls = None
                site(ty, i, "tuple constructor")
            elif nxt == "::" and re.match(r"[A-Za-z_]", t[j + 1]) and t[j + 2] != "{":
                cls = "a path to an associated item"
            elif nxt == "::":
                cls = None
                loose.append(f"{s.rel}:{tok.line}: `{tok}::{t[j + 1]} {t[j + 2]}`")
            elif fish:
                cls = None
                site(ty, i, "the constructor as a function")
            elif nxt == "<":
                cls = "a type with its arguments"
            elif s.in_header(i):
                cls = "a type in a signature or an impl line"
            elif tok.line in use_lines[s.name]:
                cls = "a `use` item"
            elif prev == "type" and nxt == "=" and tok in ALIASES:
                cls = "an alias's definition"
            elif is_self and prev == "where" and nxt == ":":
                cls = "a `where Self:` clause"
            elif ty in TUPLE and tok not in ALIASES:
                cls = None                       # a tuple struct's bare name is its constructor
                site(ty, i, "the constructor as a function")
            else:
                cls = None
                loose.append(f"{s.rel}:{tok.line}: `{prev} {tok} {nxt}`")
            if cls:
                classes[cls] = classes.get(cls, 0) + 1
    rep.line(f"(in test modules, not part of the argument: {test_sites})")
    rep.line("every other mention: " + "; ".join(f"{k}: {v}" for k, v in sorted(classes.items())))
    rep.line(f"mentions in no class: {len(loose)}")
    rep.expect(not loose, f"a mention of a key type in no class: {loose}")
    rep.same(sites, I1_SITES, "construction sites")

    rep.section("4. nothing takes a key by `&mut`, and fields are assigned only while a key is built")
    mut_recv, mut_param, writes = [], [], set()
    for s in srcs:
        t = s.toks
        for it in s.items:
            if it.kind == "fn" and not it.test and self_type(s, it.start) in SIX:
                h = R.join(it.header)
                if re.search(r"&mut self|\(mut self|&'[a-z_]+ mut self", h):
                    mut_recv.append(f"{s.rel}:{it.line} {it.name}")
        for i in range(len(t) - 2):
            if t[i] == "&" and t[i + 1] == "mut" and t[i + 2] in SIX and not s.is_test(i):
                mut_param.append(f"{s.rel}:{t[i].line}")
            if s.name in ("keys.rs", "rsasve.rs") and t[i] == "." and t[i + 2] == "=" and not s.is_test(i) \
                    and re.match(r"[a-z_0-9]+$", t[i + 1]):
                fn = s.fn_at(i)
                writes.add((s.name, fn.name if fn else "?", str(t[i + 1])))
                rep.line(f"{s.rel}:{t[i].line}: field `{t[i + 1]}` assigned in fn {fn.name if fn else '?'}")
    rep.line(f"methods of a key type with a `&mut self` or `mut self` receiver: {len(mut_recv)}")
    rep.line(f"parameters of type `&mut <key type>` anywhere in the crate: {len(mut_param)}")
    rep.expect(not mut_recv, f"mutable receivers: {mut_recv}")
    rep.expect(not mut_param, f"&mut key parameters: {mut_param}")
    rep.same(writes, I1_FIELD_WRITES, "field assignments")

    rep.section("5. every function that returns a key, or hands one to a closure")
    returning = set()
    for s in srcs:
        for it in s.items:
            if it.kind != "fn" or it.test:
                continue
            h = it.header
            st = self_type(s, it.start)
            arrow = max((j for j, x in enumerate(h) if x == "->"), default=None)
            ret = h[arrow + 1:] if arrow is not None else []
            if "where" in ret:
                ret = ret[:ret.index("where")]
            # `Self` as the type itself: `Self::Signer<'k>` is an associated type, not a key
            own = [x for j, x in enumerate(ret) if x == "Self" and not (j + 1 < len(ret) and ret[j + 1] == "::")]
            hands = "FnOnce" in h and (any(x in SIX for x in h) or ("Self" in h and st in SIX))
            gives = any(x in SIX for x in ret) or (bool(own) and st in SIX)
            if gives or hands:
                returning.add((s.name, st, it.name))
                p = it.parent
                vis = "trait" if p is not None and (p.kind == "trait" or R.impl_parts(p)[0]) else it.vis
                rep.line(f"{s.rel}:{it.line}: {vis:10s} {st}::{it.name}" + ("   [hands the key to `finish`]" if hands and not gives else ""))
    rep.same(returning, I1_RETURNING, "functions that return a key")

    rep.section("6. the size traits are sealed: the six markers are the only sizes")
    size = by["size.rs"]
    for it in size.items:
        if it.kind == "trait" and it.name in ("RsaSize", "RsaSigningSize") and not it.test:
            rep.line(f"{size.rel}:{it.line}: {it.vis} {it.text(120)}")
    rsa_size = next(it for it in size.items if it.kind == "trait" and it.name == "RsaSize")
    rep.expect("sealed::Sealed" in R.join(rsa_size.header).replace(" ", ""), "RsaSize does not name sealed::Sealed")
    signing = next(it for it in size.items if it.kind == "trait" and it.name == "RsaSigningSize")
    rep.expect("RsaSize" in signing.header, "RsaSigningSize is not a subtrait of RsaSize")
    sealed_mod = [it for it in size.items if it.kind == "mod" and it.name == "sealed"]
    rep.expect(len(sealed_mod) == 1 and sealed_mod[0].vis == "private", "size.rs's `sealed` module is not private")
    if sealed_mod:
        rep.line(f"{size.rel}:{sealed_mod[0].line}: {sealed_mod[0].vis} mod sealed")
    impls = set()
    for it in size.items:
        if it.kind == "impl" and not it.test:
            tr, ty = R.impl_parts(it)
            if tr == "Sealed":
                impls.add(ty)
                rep.line(f"{size.rel}:{it.line}: {it.text()}")
    rep.same(impls, SEALED_SIZES, "impls of sealed::Sealed")
    lens = [t.line for i, t in enumerate(size.toks) if t == "check_lengths" and size.toks[i - 1] == "=" ]
    rep.line(f"`const _: () = check_lengths::<..>()` beside the impls, at {size.rel}:{', '.join(map(str, lens))}")
    rep.expect(len(lens) == 6, f"{len(lens)} check_lengths constants, not 6")
    return rep.verdict("I1 SEARCH")


# =================================================================================== roles
ROLE = {}
ROLE.update(dict.fromkeys(("EncapsulatingKey", "KEMEncapsulator", "KeyTransportEncryptingKey"), "public key: encapsulates or transports"))
ROLE.update(dict.fromkeys(("DecapsulatingKey", "KEMDecapsulator", "KeyTransportDecryptingKey"), "private key: decapsulates or recovers"))
ROLE.update(dict.fromkeys(("SigningKey", "OneShotSigningKey", "DeterministicSigningKey",
                           "DeterministicOneShotSigningKey", "SignatureSigner"), "private key: signs"))
ROLE.update(dict.fromkeys(("VerifyingKey", "OneShotVerifyingKey", "SignatureVerifier"), "public key: verifies"))
# what the audit states: the role impls there are, as (file, trait, self type)
ROLE_IMPLS = {
    ("rsasve.rs", "KEMEncapsulator", "RsasveEncapsulator"), ("rsasve.rs", "KEMDecapsulator", "RsasveDecapsulator"),
    ("rsasve.rs", "EncapsulatingKey", "RsaKEMPublicKey"), ("rsasve.rs", "DecapsulatingKey", "RsaKEMPrivateKey"),
    ("rsasve_kdf.rs", "KEMEncapsulator", "RsasveKdfEncapsulator"), ("rsasve_kdf.rs", "KEMDecapsulator", "RsasveKdfDecapsulator"),
    ("rsasve_kdf.rs", "EncapsulatingKey", "RsaKEMPublicKey"), ("rsasve_kdf.rs", "DecapsulatingKey", "RsaKEMPrivateKey"),
    ("rsaes_oaep.rs", "KEMEncapsulator", "RsaOaepEncapsulator"), ("rsaes_oaep.rs", "KEMDecapsulator", "RsaOaepDecapsulator"),
    ("rsaes_oaep.rs", "EncapsulatingKey", "RsaKEMPublicKey"), ("rsaes_oaep.rs", "DecapsulatingKey", "RsaKEMPrivateKey"),
    ("rsaes_oaep.rs", "KeyTransportEncryptingKey", "RsaKEMPublicKey"),
    ("rsaes_oaep.rs", "KeyTransportDecryptingKey", "RsaKEMPrivateKey"),
    ("rsassa.rs", "SigningKey", "RsaPrivateKey"), ("rsassa.rs", "OneShotSigningKey", "RsaPrivateKey"),
    ("rsassa.rs", "DeterministicSigningKey", "RsaPrivateKey"),
    ("rsassa.rs", "DeterministicOneShotSigningKey", "RsaPrivateKey"),
    ("rsassa.rs", "SignatureSigner", "RsaSigner"), ("rsassa.rs", "SignatureSigner", "RsaDeterministicSigner"),
    ("rsassa.rs", "VerifyingKey", "RsaPublicKey"), ("rsassa.rs", "OneShotVerifyingKey", "RsaPublicKey"),
    ("rsassa.rs", "SignatureVerifier", "RsaVerifier"),
}
# every call of the raw public primitive: (file, function it stands in) -> why the size there is what it is
PUBLIC_EXP_CALLS = {
    ("rsa_core.rs", "rsavp1"): "signature verification: any size, by design (the crate's Scope)",
    ("rsa_core.rs", "crt_exp_checked_in_own_frame"): "the result check of a private-key operation: reached from RsaSigningSize::crt_exp only",
    ("rsasve.rs", "encaps_out"): "RSASVE.GENERATE: inside the impl bounded by RsaSigningSize",
    ("rsaes_oaep.rs", "encrypt"): "RSAES-OAEP-ENCRYPT: the function is bounded by RsaSigningSize",
    ("size.rs", "public_exp"): "the size's own routing to rsa_core::public_exp: the public method (observation N14)",
}


def size_bound(header):
    return "RsaSigningSize" if "RsaSigningSize" in header else ("RsaSize" if "RsaSize" in header else "(none named)")


def search_roles(root):
    rep = Report("Roles and the size they are bounded by (finding F-04, row (b))")
    srcs = load(root, rsa_files(root))

    rep.section("1. every impl of a role trait, with the bound on its size parameter")
    found = set()
    print(f"   {'role':40s} {'trait':31s} {'for':24s} {'bound':15s} where")
    for s in srcs:
        for it in s.items:
            if it.kind != "impl" or it.test:
                continue
            tr, ty = R.impl_parts(it)
            if tr not in ROLE:
                continue
            bound = size_bound(it.header)
            found.add((s.name, tr, ty))
            print(f"   {ROLE[tr]:40s} {tr:31s} {ty:24s} {bound:15s} {s.rel}:{it.line}")
            if ROLE[tr].endswith("verifies"):
                rep.expect(bound == "RsaSize", f"{s.name}:{it.line}: a verifying role is not at every size")
            else:
                rep.expect(bound == "RsaSigningSize", f"{s.name}:{it.line}: {tr} for {ty} is bounded by {bound}")
    rep.same(found, ROLE_IMPLS, "role impls")
    enc = [x for x in found if ROLE[x[1]].startswith("public key: enc")]
    rep.line(f"encapsulating or transporting impls: {len(enc)}, every one bounded by RsaSigningSize; "
             "bounded by RsaSize alone: " + str(sum(1 for s in srcs for it in s.items if it.kind == 'impl' and not it.test
                                                    and R.impl_parts(it)[0] in ROLE and ROLE[R.impl_parts(it)[0]].startswith('public key: enc')
                                                    and size_bound(it.header) != 'RsaSigningSize')))

    rep.section("2. every other impl in the three key-establishment files, with its bound (naming and key plumbing)")
    for s in srcs:
        if s.name not in ("rsasve.rs", "rsasve_kdf.rs", "rsaes_oaep.rs"):
            continue
        for it in s.items:
            if it.kind == "impl" and not it.test and R.impl_parts(it)[0] not in ROLE \
                    and size_bound(it.header) != "(none named)":
                tr, ty = R.impl_parts(it)
                fns = [c.name for c in it.children if c.kind == "fn"]
                rep.line(f"{s.rel}:{it.line}: {size_bound(it.header):15s} impl {tr or '(inherent)'} for {ty}: {', '.join(fns) or '-'}")

    rep.section("3. every call of the raw primitives, with the bound it stands under")
    calls = set()
    for s in srcs:
        t = s.toks
        for i, tok in enumerate(t):
            if tok not in ("public_exp", "crt_exp") or s.is_test(i) or i == 0 or i + 1 >= len(t):
                continue
            if t[i - 1] == "fn" or t[i + 1] not in ("(", "::"):
                continue
            fn, im = s.fn_at(i), s.impl_at(i)
            b_fn = size_bound(fn.header) if fn else "-"
            b_im = size_bound(im.header) if im else "-"
            callee = R.join(t[i - 2:i + 1]) if t[i - 1] == "::" else str(tok)
            rep.line(f"{s.rel}:{tok.line}: {callee:32s} in fn {fn.name if fn else '?':30s} fn bound: {b_fn:15s} impl bound: {b_im}")
            if tok == "public_exp":
                calls.add((s.name, fn.name if fn else "?"))
            else:
                rep.expect("RsaSigningSize" in (b_fn, b_im) or s.name == "rsa_core.rs" or s.name == "size.rs",
                           f"{s.name}:{tok.line}: crt_exp called outside a signing size")
    rep.same(calls, PUBLIC_EXP_CALLS, "callers of public_exp")
    for (f, fn), why in sorted(PUBLIC_EXP_CALLS.items()):
        rep.line(f"{f}: {fn}: {why}")

    rep.section("4. what remains at the verify-only sizes (observation N14)")
    size = next(s for s in srcs if s.name == "size.rs")
    for it in size.items:
        if it.kind == "fn" and it.name == "public_exp" and not it.test:
            im = it.parent
            where = im.name if im.kind == "trait" else R.impl_parts(im)[1]
            rep.line(f"{size.rel}:{it.line}: {where}::public_exp   (a public trait's method: callable at every size)")
    return rep.verdict("ROLES SEARCH")


# ===================================================================================== m10
# M10's inventory: every function with const generic parameters that code outside the crate can
# name, as (file, owner, name) -> (relation, how it is asserted). `how`:
#   ("const", <word>)  a `const { .. }` block in the body that contains <word>
#   ("via", <callee>)  the body instantiates <callee> with the same parameters, and <callee>
#                      asserts; listed under its own row
#   ("type", <word>)   the header binds the parameter by a type equality that contains <word>
#   ("free", <why>)    no relation is needed, or the parameter is a length with a rule of its
#                      own that is not one of M10's
M10 = {
    # crypto/rsa/src/modexp.rs
    ("modexp.rs", "-", "mul_mod"): ("L2 = 2L, L21 = 2L + 1", ("const", "check_widths")),
    ("modexp.rs", "-", "mod_pow"): ("L2 = 2L, L21 = 2L + 1", ("const", "check_widths")),
    ("modexp.rs", "-", "mod_pow_public_exponent"): ("L2 = 2L, L21 = 2L + 1", ("const", "check_widths")),
    ("modexp.rs", "-", "sub_mod"): ("one width", ("free", "a single parameter")),
    ("modexp.rs", "-", "reduce_wide"): ("none: WIDE and NARROW are independent (M8 holds for all widths)", ("free", "no relation")),
    # crypto/rsa/src/keygen.rs
    ("keygen.rs", "-", "is_probable_prime"): ("N2 = 2N, N21 = 2N + 1", ("const", "check_widths")),
    ("keygen.rs", "-", "keygen_from_rng"): ("HALF2 = 2 HALF, HALF21 = 2 HALF + 1; HALF and HALF2 are also K's limb counts",
                                            ("const", "check_widths")),
    # crypto/rsa/src/rsassa.rs: the four *_from_hash entry points and the signer's salt
    ("rsassa.rs", "-", "sign_from_hash_with_salt"): ("K_LEN = K::K_LEN", ("type", "Modulus")),
    ("rsassa.rs", "-", "sign_from_hash"): ("K_LEN = K::K_LEN", ("type", "Modulus")),
    ("rsassa.rs", "-", "sign_from_hash_deterministic"): ("K_LEN = K::K_LEN", ("type", "Modulus")),
    ("rsassa.rs", "-", "verify_from_hash"): ("K_LEN = K::K_LEN", ("type", "Modulus")),
    ("rsassa.rs", "RsaSigner", "set_salt"): ("N = A::SALT_LEN (a length, not a width)", ("const", "SALT_LEN")),
    # the algorithm traits' encodings: declared in rsassa.rs, defined in the two scheme files
    ("rsassa.rs", "RsaSignatureAlgorithm", "emsa_verify"): ("K_LEN = K::K_LEN", ("free", "a declaration: asserted in each impl")),
    ("rsassa.rs", "RsaDeterministicSignatureAlgorithm", "emsa_encode"): ("K_LEN = K::K_LEN", ("free", "a declaration: asserted in each impl")),
    ("rsassa.rs", "RsaRandomizedSignatureAlgorithm", "emsa_encode"): ("K_LEN = K::K_LEN", ("free", "a declaration: asserted in each impl")),
    ("rsassa_pkcs1_v1_5.rs", "RSASSA_PKCS1_v1_5", "emsa_verify"): ("K_LEN = K::K_LEN", ("const", "K_LEN")),
    ("rsassa_pkcs1_v1_5.rs", "RSASSA_PKCS1_v1_5", "emsa_encode"): ("K_LEN = K::K_LEN", ("const", "K_LEN")),
    ("rsassa_pss.rs", "RSASSA_PSS", "emsa_verify"): ("K_LEN = K::K_LEN", ("const", "K_LEN")),
    ("rsassa_pss.rs", "RSASSA_PSS", "emsa_encode"): ("K_LEN = K::K_LEN", ("const", "K_LEN")),
    # crypto/rsa/src/rsaes_oaep.rs: a buffer's capacity, not a width
    ("rsaes_oaep.rs", "RsaKEMPrivateKey", "recover_out"): ("KEY_LEN is the caller's buffer (a capacity, not a width)", ("free", "no relation")),
    # crypto/ec/src/montgomery.rs
    ("montgomery.rs", "-", "widening_mul"): ("L2 = 2L", ("via", "widening_mul_into")),
    ("montgomery.rs", "-", "widening_mul_into"): ("L2 = 2L", ("const", "L2")),
    ("montgomery.rs", "-", "widening_square"): ("L2 = 2L", ("const", "L2")),
    ("montgomery.rs", "-", "redc"): ("L2 = 2L, L21 = 2L + 1", ("const", "L21")),
    # crypto/ec/src/barrett.rs
    ("barrett.rs", "-", "reduce"): ("L2 = 2L, L1 = L + 1", ("via", "reduce_into")),
    ("barrett.rs", "-", "reduce_into"): ("L2 = 2L, L1 = L + 1", ("const", "L1")),
    ("barrett.rs", "-", "limbs_from_be_bytes"): ("one width; a slice longer than 8 L2 bytes is a documented panic (a run-time assert)", ("free", "a single parameter")),
    ("barrett.rs", "-", "limbs_from_be_bytes_into"): ("one width; the same run-time assert", ("free", "a single parameter")),
}
# The crate's own instantiations with literal widths, and the relation each must satisfy.
ROUTING = {
    "limbs_from_be_bytes": lambda a: len(a) == 2 and a[1] == 8 * a[0],
    "be_bytes_from_limbs": lambda a: len(a) == 2 and a[1] == 8 * a[0],
    "public_exp": lambda a: len(a) == 3 and a[1] == 2 * a[0] and a[2] == 2 * a[0] + 1,
    "crt_exp_checked": lambda a: len(a) == 6 and a[1] == 2 * a[0] and a[2] == 2 * a[0] + 1 and a[0] == 2 * a[3]
                                 and a[4] == 2 * a[3] and a[5] == 2 * a[3] + 1,
    "keygen_from_rng": lambda a: len(a) == 3 and a[1] == 2 * a[0] and a[2] == 2 * a[0] + 1,
    "widening_mul": lambda a: len(a) == 2 and a[1] == 2 * a[0],
}


def const_params(item):
    """Names of the const generic parameters in an fn's or impl's own generics."""
    h = item.header
    lt = next((j for j, x in enumerate(h[:4]) if x == "<"), None)
    if item.kind == "fn":
        lt = 2 if len(h) > 2 and h[2] == "<" else None
    elif item.kind == "impl":
        lt = 1 if len(h) > 1 and h[1] == "<" else None
    if lt is None:
        return []
    gt = R.angle_close(h, lt)
    return [str(h[j + 1]) for j in range(lt, gt) if h[j] == "const"]


def const_blocks(src, item):
    """[(line, text)] of the `const { .. }` blocks in an fn's body."""
    t, out = src.toks, []
    if t[item.header_end] != "{":
        return out
    for i in range(item.header_end, item.end):
        if t[i] == "const" and t[i + 1] == "{":
            out.append((t[i].line, R.join(t[i:R.close_of(t, i + 1) + 1])))
    return out


def search_m10(root):
    rep = Report("M10: the width relations of public generic functions (finding F-06, row (b))")
    rsa = load(root, rsa_files(root))
    ec = load(root, ["crypto/ec/src/montgomery.rs", "crypto/ec/src/barrett.rs"])
    by = {s.name: s for s in rsa}

    rep.section("1. which modules code outside the crates can name")
    pub_mods = {}
    for lib, files in ((by["lib.rs"], rsa), (Src(root, "crypto/ec/src/lib.rs"), ec)):
        mods = re.findall(r"^(pub )?mod ([a-z_0-9]+);", lib.text, re.M)
        for vis, name in mods:
            pub_mods[(os.path.dirname(lib.rel), name)] = bool(vis)
        shown = [f"{'pub ' if v else ''}mod {m}" for v, m in mods if any(f.name == m + ".rs" for f in files)]
        rep.line(f"{lib.rel}: " + "; ".join(shown))
    reexports = re.findall(r"^pub use ([^;]+);", by["lib.rs"].text, re.M)
    rep.line(f"{by['lib.rs'].rel}: re-exports: {reexports}")
    rep.expect(reexports == ["size::{RSA1024, RSA1536, RSA2048, RSA3072, RSA4096, RSA8192}"],
               "lib.rs re-exports something other than the six size markers")

    def module_public(s):
        return pub_mods.get((os.path.dirname(s.rel), s.name[:-3]), False)

    def reachable(s, it):
        """Whether a function can be named from outside its crate, by syntax: its module is
        `pub`, and it is `pub` itself, or a method of a trait, or a method of a trait impl."""
        if not module_public(s):
            return False, "module is private to the crate"
        p = it.parent
        if p is None:
            return it.vis == "pub", f"{it.vis} fn"
        if p.kind == "trait":
            return p.vis == "pub", f"method of {p.vis} trait {p.name}"
        if p.kind == "impl":
            tr, ty = R.impl_parts(p)
            if tr is not None:
                return True, f"method of impl {tr} for {ty}"
            return it.vis == "pub", f"{it.vis} method of {ty}"
        return False, f"inside {p.kind} {p.name}"

    rep.section("2. every function with const generic parameters of its own")
    print(f"   {'where':38s} {'function':44s} {'const parameters':24s} reach")
    public_generic, all_rows = {}, 0
    for s in rsa + ec:
        for it in s.items:
            if it.kind != "fn" or it.test:
                continue
            cp = const_params(it)
            if not cp:
                continue
            all_rows += 1
            ok, why = reachable(s, it)
            owner = "-"
            if it.parent is not None and it.parent.kind in ("impl", "trait"):
                owner = it.parent.name if it.parent.kind == "trait" else (R.impl_parts(it.parent)[1] or "-")
            name = f"{owner + '::' if owner != '-' else ''}{it.name}"
            print(f"   {s.rel + ':' + str(it.line):38s} {name:44s} {', '.join(cp):24s} {'PUBLIC' if ok else 'crate'}: {why}")
            if ok:
                public_generic.setdefault((s.name, owner, it.name), []).append((s, it, cp))
    rep.line(f"{all_rows} functions; {sum(len(v) for v in public_generic.values())} of them public")
    rep.same(public_generic.keys(), M10.keys(), "public generic functions")

    rep.section("3. the inventory: relation, and where it is asserted")
    for key in sorted(M10, key=lambda k: (k[0] not in ("modexp.rs", "keygen.rs"), k)):
        relation, (how, word) = M10[key]
        for s, it, cp in public_generic.get(key, []):
            blocks = const_blocks(s, it)
            where = "-"
            if how == "const":
                hit = [(ln, txt) for ln, txt in blocks if word in txt]
                rep.expect(bool(hit), f"{s.name}:{it.line} {it.name}: no const block naming {word}")
                where = "; ".join(f"const block at {s.name}:{ln}: {txt[:88]}" for ln, txt in hit)
            elif how == "via":
                body = R.join(s.toks[it.header_end:it.end])
                generic_args = ", ".join(cp)
                call = re.search(re.escape(word) + r"(::<([^>]*)>)?\(", body)
                rep.expect(call is not None, f"{s.name}:{it.line} {it.name}: does not call {word}")
                if call and call.group(2):
                    rep.expect(call.group(2).replace(" ", "") == generic_args.replace(" ", ""),
                               f"{s.name}:{it.line} {it.name}: calls {word} with other parameters: {call.group(2)}")
                rep.expect(not blocks or True, "")
                where = f"instantiates {word}" + (f"::<{call.group(2)}>" if call and call.group(2) else " with its own parameters (inferred from the argument types)") + ", which asserts"
            elif how == "type":
                h = R.join(it.header)
                m = re.search(r"[A-Za-z]+ = \[u(8|64); ?([A-Z_0-9]+)\]", h)
                rep.expect(word in h and m is not None and m.group(2) in cp, f"{s.name}:{it.line} {it.name}: no type equality on {word}")
                where = f"bound in the signature: {m.group(0) if m else '?'}"
            else:
                rep.expect(not blocks or key[2] in ("recover_out",), f"{s.name}:{it.line} {it.name}: has a const block the table does not mention")
                where = word
            print(f"   {s.rel}:{it.line}: {key[1] + '::' if key[1] != '-' else ''}{key[2]}<{', '.join(cp)}>")
            print(f"        relation: {relation}")
            print(f"        asserted: {where}")

    rep.section("4. impl blocks with const generic parameters: how each parameter is fixed")
    for s in rsa:
        if not module_public(s):
            continue
        for it in s.items:
            if it.kind != "impl" or it.test:
                continue
            cp = const_params(it)
            if not cp:
                continue
            h = R.join(it.header)
            tr, ty = R.impl_parts(it)
            fixed = []
            for c in cp:
                m = re.search(r"([A-Za-z]+) = \[u(?:8|64); ?" + c + r"\]", h)
                if m:
                    fixed.append(f"{c}: the size's {m.group(1)}")
                else:
                    blocks = [(ln, txt) for ch in it.children if ch.kind == "fn" for ln, txt in const_blocks(s, ch) if c in txt]
                    if blocks:
                        fixed.append(f"{c}: a length, checked in const blocks at lines {', '.join(str(ln) for ln, _ in blocks)}")
                    else:
                        fixed.append(f"{c}: free (a length the trait names; no width relation)")
            rep.line(f"{s.rel}:{it.line}: impl {tr or '(inherent)'} for {ty}: " + "; ".join(fixed))

    rep.section("5. the crate's own instantiations with literal widths (the routing table), checked numerically")
    counts = {}
    for s in rsa:
        t = s.toks
        for i, tok in enumerate(t):
            if tok in ROUTING and i + 2 < len(t) and t[i + 1] == "::" and t[i + 2] == "<" and not s.is_test(i):
                gt = R.angle_close(t, i + 2)
                args = [str(x) for x in t[i + 3:gt] if x != ","]
                nums = [int(x) for x in args if x.isdigit()]
                if len(nums) < 2 or len(nums) != len([x for x in args if x != "Self"]):
                    continue                      # a generic instantiation: covered by its own const block
                ok = ROUTING[tok](nums)
                counts.setdefault(tok, []).append((s.name, tok.line, nums, ok))
                rep.expect(ok, f"{s.name}:{tok.line}: {tok}::<{', '.join(args)}> breaks its relation")
    for fn, rows in sorted(counts.items()):
        tuples = sorted({tuple(r[2]) for r in rows})
        rep.line(f"{fn}: {len(rows)} literal instantiations, all in relation: " + ", ".join("<" + ", ".join(map(str, tp)) + ">" for tp in tuples))
    rep.expect(sum(len(v) for v in counts.values()) > 0, "no literal instantiation found")

    rep.section("6. width relations that are still debug assertions")
    for s in rsa + ec:
        t = s.toks
        for i, tok in enumerate(t):
            if tok in ("debug_assert", "debug_assert_eq") and not s.is_test(i):
                end = R.close_of(t, i + 2)
                txt = R.join(t[i:end + 1])
                if re.search(r"\b(BYTES|K_LEN|L2|L21|L1|N2|N21|HALF2|HALF21)\b", txt) and "[" not in txt:
                    fn = s.fn_at(i)
                    rep.line(f"{s.rel}:{tok.line}: in {fn.name if fn else '?'} ({'public module' if module_public(s) else 'module private to the crate'}): {txt[:110]}")
    return rep.verdict("M10 SEARCH")


# ================================================================================= control
# A search that cannot fail proves nothing. Each line below is one edit to a copy of the
# source that the documents say upstream has not made; the search named must report it.
MUTATIONS = (
    ("i1", "a constructor that skips the checks", "keys.rs",
     "impl<K: RsaSize> RsaPublicComponents<K> {",
     "impl<K: RsaSize> RsaPublicComponents<K> {\n    pub fn unchecked(n: &K::Limbs, e: u64) -> Self {\n        Self { n: *n, e }\n    }\n"),
    ("i1", "a public field", "keys.rs", "    n: K::Limbs,\n    e: u64,\n}", "    pub n: K::Limbs,\n    e: u64,\n}"),
    ("i1", "a method that takes a key by &mut", "rsasve.rs",
     "    /// The public exponent `e`.\n    pub fn e(&self) -> u64 {\n        self.0.e()\n    }",
     "    pub fn e(&self) -> u64 {\n        self.0.e()\n    }\n    pub fn replace(&mut self, other: Self) {\n        *self = other;\n    }"),
    ("i1", "a tuple constructor outside from_rsa_key", "rsasve_kdf.rs",
     "const fn len_check<", "fn forged<K: RsaSize>(pk: crate::keys::RsaPublicComponents<K>) -> RsaKEMPublicKey<K> {\n    RsaKEMPublicKey(pk)\n}\n\nconst fn len_check<"),
    ("i1", "a constructor written on an alias of a key type", "rsa_2048.rs",
     "/// Length of an RSASVE-2048 ciphertext",
     "impl RSA2048KEMPublicKey {\n    pub fn forged(pk: crate::keys::RsaPublicComponents<RSA2048>) -> Self {\n        Self(pk)\n    }\n}\n\n/// Length of an RSASVE-2048 ciphertext"),
    ("i1", "a tuple constructor passed as a function", "rsasve_kdf.rs",
     "const fn len_check<", "fn forged<K: RsaSize>(pk: Option<crate::keys::RsaPublicComponents<K>>) -> bool {\n    pk.map(RsaKEMPublicKey).is_some()\n}\n\nconst fn len_check<"),
    ("i1", "a tuple key written with braces", "rsasve_kdf.rs",
     "const fn len_check<", "fn forged<K: RsaSize>(pk: crate::keys::RsaPublicComponents<K>) -> bool {\n    let key = RsaKEMPublicKey { 0: pk };\n    key.e() == 3\n}\n\nconst fn len_check<"),
    ("i1", "a struct expression with generic arguments", "keys.rs",
     "impl<K: RsaSize> RsaPublicComponents<K> {",
     "impl<K: RsaSize> RsaPublicComponents<K> {\n    fn unchecked_e(n: &K::Limbs, e: u64) -> u64 {\n        let key = RsaPublicComponents::<K> { n: *n, e };\n        key.e\n    }\n"),
    ("i1", "a key written through an associated type", "size.rs",
     "        keygen_as::<K, _, _>(rng, crate::rsasve::keygen_from::<K>)\n",
     "        let _forge = |pk: RsaPublicComponents<K>| Self::PublicKey { 0: pk };\n        keygen_as::<K, _, _>(rng, crate::rsasve::keygen_from::<K>)\n"),
    ("i1", "a key written through an associated type of a parameter", "rsasve_kdf.rs",
     "const fn len_check<", "fn forged<K>(pk: crate::keys::RsaPublicComponents<K>) -> bool\nwhere\n    K: RsaSigningSize + crate::size::KemKeyPair<PublicKey = RsaKEMPublicKey<K>>,\n{\n    let key = K::PublicKey { 0: pk };\n    key.e() == 3\n}\n\nconst fn len_check<"),
    ("i1", "an alias of an alias of a key type", "rsa_2048.rs",
     "/// Length of an RSASVE-2048 ciphertext", "type Again = RSA2048KEMPublicKey;\n\n/// Length of an RSASVE-2048 ciphertext"),
    ("i1", "an alias of an associated type that is a key", "rsasve_kdf.rs",
     "const fn len_check<", "type Projected<K> = <K as crate::size::KemKeyPair>::PublicKey;\n\nconst fn len_check<"),
    ("i1", "a derive from a dependency", "keys.rs",
     "#[derive(Clone, Debug, PartialEq, Eq)]\npub struct RsaPublicComponents", "#[derive(Clone, Debug, PartialEq, Eq, FromBytes)]\npub struct RsaPublicComponents"),
    ("i1", "a trait that makes a key from nothing", "keys.rs",
     "/// Whether the modulus's top bit is set", "impl<K: RsaSize> Default for RsaPublicComponents<K> {\n    fn default() -> Self {\n        unimplemented!()\n    }\n}\n\n/// Whether the modulus's top bit is set"),
    ("roles", "an encapsulating impl at every size", "rsasve.rs",
     "    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,", "    K: RsaSize<Modulus = [u8; N]>,"),
    ("roles", "a new caller of the public primitive", "rsasve_kdf.rs",
     "const fn len_check<", "fn raw<K: RsaSize>(n: &K::Limbs, x: &K::Limbs) -> K::Limbs {\n    K::public_exp(n, 65537, x)\n}\n\nconst fn len_check<"),
    ("m10", "a width check removed", "modexp.rs", "    const { check_widths::<L, L2, L21>() };\n", ""),
    ("m10", "a new public generic function", "modexp.rs",
     "pub fn sub_mod<", "pub fn extra<const L: usize, const L2: usize>(_a: &[u64; L]) -> [u64; L2] {\n    [0; L2]\n}\n\npub fn sub_mod<"),
    ("m10", "a routing entry out of relation", "size.rs", "limbs_from_be_bytes::<16, 128>(bytes)", "limbs_from_be_bytes::<16, 120>(bytes)"),
)


def control(root):
    """Runs each search on a copy of the source with one of MUTATIONS applied."""
    import contextlib
    import io
    import shutil
    import tempfile
    runs = {"i1": search_i1, "roles": search_roles, "m10": search_m10}
    print("\n=== control: each search on a copy of the source with one edit")
    missed = 0
    with tempfile.TemporaryDirectory() as tmp:
        for d in (RSA, "crypto/ec/src"):
            shutil.copytree(os.path.join(root, d), os.path.join(tmp, d))
        for which, what, name, old, new in MUTATIONS:
            path = os.path.join(tmp, RSA, name)
            original = open(path).read()
            if old not in original:
                print(f"   {which:5s} {what}: THE EDIT DOES NOT APPLY ({name})")
                missed += 1
                continue
            open(path, "w").write(original.replace(old, new, 1))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                as_stated = runs[which](tmp)
            open(path, "w").write(original)
            hits = [l.strip() for l in buf.getvalue().splitlines() if "DEVIATION:" in l]
            print(f"   {which:5s} {what}: " + (f"reported ({len(hits)}): {hits[0][11:120]}" if not as_stated else "NOT REPORTED"))
            missed += as_stated
    print(f"control: {len(MUTATIONS) - missed} of {len(MUTATIONS)} edits reported")
    return missed == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("which", nargs="?", default="all", choices=("i1", "roles", "m10", "all"))
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    ap.add_argument("--no-control", action="store_true", help="skip the control (the edited copies)")
    a = ap.parse_args()
    runs = {"i1": search_i1, "roles": search_roles, "m10": search_m10}
    ok = True
    for name in (runs if a.which == "all" else (a.which,)):
        ok &= runs[name](a.root)
    if not a.no_control:
        global MUTATIONS
        if a.which != "all":
            MUTATIONS = tuple(m for m in MUTATIONS if m[0] == a.which)
        ok &= control(a.root)
    print("\nLISTED SEARCHES: " + ("ALL AS STATED, EVERY CONTROL EDIT REPORTED" if ok else "DEVIATIONS FOUND"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
