#!/usr/bin/env python3
"""Function-level diff of Rust sources between two git revisions.

Plan WP14.1, second item: "confirm what §2.1 takes as unchanged, by a diff of
b7e46cb against the pin with comment lines and assertion lines dropped".

For each file, every `fn` item is cut out at both revisions (comments removed,
string and char literals kept as single tokens), and its token stream is
compared three ways:

  SAME          identical tokens
  SAME-ASSERT   identical once assertion statements are dropped
                (debug_assert*!, assert*!, and inline `const { ... }` blocks)
  CHANGED       differs beyond that: the normalized diff is printed

Functions present on one side only are NEW or GONE.  A function is keyed by
its enclosing impl/trait/mod header plus its name, so two `new`s do not
collide.  Nothing here interprets Rust beyond brace matching: the tool can say
"same tokens", never "same meaning" for a CHANGED body.

Usage:  fn_diff.py <repo> <old-rev> <new-rev> <path> [<path> ...]
            [--map OLD=NEW ...]   compare old function OLD with new function NEW
                                  (a rename, or a body moved into another function);
                                  names are the last component of the key
            [--quiet]             list SAME verdicts as a count only
Exit status 0 always; the verdict table is the output.
"""
import difflib
import re
import subprocess
import sys


def git_show(repo, rev, path):
    r = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"],
                       capture_output=True)
    if r.returncode != 0:
        return None
    return r.stdout.decode("utf-8")


TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<lc>//[^\n]*)
  | (?P<id>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<num>[0-9][A-Za-z0-9_.]*)
  | (?P<punct>::|->|=>|==|!=|<=|>=|&&|\|\||<<=|>>=|<<|>>|\+=|-=|\*=|/=|%=|\^=|&=|\|=|\.\.=|\.\.|.)
""", re.X | re.S)


def lex(src):
    """Tokens with comments removed.  Strings, raw strings, byte strings and
    char literals come out as one token each; lifetimes as one token."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        # block comment, nested
        if src.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth += 1; i += 2
                elif src.startswith("*/", i):
                    depth -= 1; i += 2
                else:
                    i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        # raw strings: r"..", r#".."#, br".."
        m = re.match(r'b?r(#*)"', src[i:])
        if m:
            hashes = m.group(1)
            end = src.find('"' + hashes, i + m.end())
            j = n if end < 0 else end + 1 + len(hashes)
            out.append(src[i:j]); i = j
            continue
        if c == '"' or (c == "b" and src.startswith('b"', i)):
            j = i + (2 if c == "b" else 1)
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1]); i = j + 1
            continue
        if c == "'" or (c == "b" and src.startswith("b'", i)):
            k = i + (1 if c == "b" else 0)
            # char literal: '\..' or 'x' followed by a quote; otherwise a lifetime
            m = re.match(r"'(\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}|.)|[^\\'])'", src[k:])
            if m:
                out.append(src[i:k + m.end()]); i = k + m.end()
                continue
            m = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", src[k:])
            if m:
                out.append(src[i:k + m.end()]); i = k + m.end()
                continue
        m = TOKEN.match(src, i)
        if m.lastgroup not in ("ws", "lc"):
            out.append(m.group(0))
        i = m.end()
    return out


def match_close(toks, i, open_, close):
    """Index just past the token that closes toks[i] == open_."""
    depth = 0
    for j in range(i, len(toks)):
        if toks[j] == open_:
            depth += 1
        elif toks[j] == close:
            depth -= 1
            if depth == 0:
                return j + 1
    return len(toks)


def functions(toks):
    """{qualified name: token list from `fn` to the end of its body}"""
    found = {}
    scopes = []          # (close index, label)
    i, n = 0, len(toks)
    last_item_start = 0
    while i < n:
        while scopes and i >= scopes[-1][0]:
            scopes.pop()
        t = toks[i]
        if t in ("impl", "trait", "mod") and (i == 0 or toks[i - 1] not in (".", "::")):
            j = i
            while j < n and toks[j] not in ("{", ";"):
                j += 1
            if j < n and toks[j] == "{":
                header = " ".join(toks[i:j])
                scopes.append((match_close(toks, j, "{", "}"), header))
                i = j + 1
                continue
        if t == "fn" and i + 1 < n and re.match(r"[A-Za-z_]", toks[i + 1]):
            name = toks[i + 1]
            j = i
            depth_p = 0
            while j < n:
                if toks[j] in ("(", "["):
                    depth_p += 1
                elif toks[j] in (")", "]"):
                    depth_p -= 1
                elif toks[j] == "{" and depth_p == 0:
                    break
                elif toks[j] == ";" and depth_p == 0:
                    break
                j += 1
            if j < n and toks[j] == "{":
                end = match_close(toks, j, "{", "}")
                label = " / ".join(s[1] for s in scopes)
                key = (label + " :: " if label else "") + name
                k, base = 2, key
                while key in found:
                    key = f"{base}#{k}"; k += 1
                found[key] = toks[i:end]
                # nested fns (rare) are still visited: step inside the body
                i = j + 1
                continue
        i += 1
    return found


ASSERT_MACROS = {"debug_assert", "debug_assert_eq", "debug_assert_ne",
                 "assert", "assert_eq", "assert_ne"}


def drop_assertions(toks):
    out = []
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t in ASSERT_MACROS and i + 2 < n and toks[i + 1] == "!" and toks[i + 2] == "(":
            j = match_close(toks, i + 2, "(", ")")
            if j < n and toks[j] == ";":
                j += 1
            i = j
            continue
        # inline const block used as a statement: `const { ... }` [;]
        if t == "const" and i + 1 < n and toks[i + 1] == "{":
            j = match_close(toks, i + 1, "{", "}")
            if j < n and toks[j] == ";":
                j += 1
            i = j
            continue
        out.append(t)
        i += 1
    return out


def pretty(toks):
    lines, cur = [], []
    for t in toks:
        cur.append(t)
        if t in (";", "{", "}"):
            lines.append(" ".join(cur)); cur = []
    if cur:
        lines.append(" ".join(cur))
    return lines


def main(argv):
    if len(argv) < 5:
        print(__doc__); return 2
    repo, old, new = argv[1:4]
    rest = argv[4:]
    quiet = "--quiet" in rest
    rest = [r for r in rest if r != "--quiet"]
    renames = {}
    if "--map" in rest:
        k = rest.index("--map")
        renames = dict(m.split("=", 1) for m in rest[k + 1:]); rest = rest[:k]
    totals = {}
    for path in rest:
        a, b = git_show(repo, old, path), git_show(repo, new, path)
        print(f"\n### {path}   {old} -> {new}")
        if a is None or b is None:
            print("   (absent at one revision)"); continue
        fa, fb = functions(lex(a)), functions(lex(b))
        same = 0
        for key in list(fa) + [k for k in fb if k not in fa]:
            if key in fa and key not in fb:
                verdict = "GONE"
            elif key not in fa:
                verdict = "NEW"
            elif fa[key] == fb[key]:
                verdict = "SAME"
            elif drop_assertions(fa[key]) == drop_assertions(fb[key]):
                verdict = "SAME-ASSERT"
            else:
                verdict = "CHANGED"
            totals[verdict] = totals.get(verdict, 0) + 1
            size = len(fb.get(key, fa.get(key)))
            if verdict == "SAME" and quiet:
                same += 1
                continue
            print(f"   {verdict:<12} {key}   ({size} tokens)")
            if verdict == "CHANGED":
                d = difflib.unified_diff(pretty(drop_assertions(fa[key])),
                                         pretty(drop_assertions(fb[key])),
                                         "old", "new", lineterm="", n=1)
                for line in d:
                    print("        " + line)
        if quiet:
            print(f"   SAME         ({same} functions, not listed)")
        # bodies compared across a rename or a move: signature line excluded,
        # so only the statements between the outer braces are compared
        def body(toks):
            i = toks.index("{")
            return drop_assertions(toks[i:])
        for old_name, new_name in renames.items():
            ka = [k for k in fa if k.split(" :: ")[-1] == old_name]
            kb = [k for k in fb if k.split(" :: ")[-1] == new_name]
            if not ka or not kb:
                continue
            ba, bb = body(fa[ka[0]]), body(fb[kb[0]])
            if ba == bb:
                print(f"   BODY-SAME    old {old_name}  ==  new {new_name}   ({len(bb)} tokens, assertions dropped)")
                totals["BODY-SAME"] = totals.get("BODY-SAME", 0) + 1
            else:
                print(f"   BODY-DIFF    old {old_name}  vs  new {new_name}")
                totals["BODY-DIFF"] = totals.get("BODY-DIFF", 0) + 1
                for line in difflib.unified_diff(pretty(ba), pretty(bb), "old", "new", lineterm="", n=1):
                    print("        " + line)
    print("\n### totals: " + ", ".join(f"{k} {v}" for k, v in sorted(totals.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
