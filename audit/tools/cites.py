#!/usr/bin/env python3
"""Every source line a document cites, printed with the text that stands there.

    python3 -I audit/tools/cites.py <bc-rust checkout> <document.md> [--all-lines]

A citation is a backticked `file.rs:N` or `file.rs:N–M`; a backticked `:N` after it on the
same line of the document continues the same file. A file named without a directory is
looked for in crypto/rsa/src, then crypto/ec/src, crypto/utils/src and crypto/core/src. Each
distinct citation is printed once, with its first and last line (all of them with
--all-lines); `??` marks a citation that names no file on its line, `!!` one that is past
the end of its file.

This judges nothing: it is for the reader who checks a document's line numbers against a
checkout (start-here: "source line numbers are never cited from recall"). The citations
that later sessions must find stale by machine are rows of audit/wp11_lines.sh.
"""
import os, re, sys
root, doc = sys.argv[1], sys.argv[2]
full = "--all-lines" in sys.argv
DIRS = ["crypto/rsa/src", "crypto/ec/src", "crypto/utils/src", "crypto/core/src"]
def resolve(name):
    if "/" in name:
        p = os.path.join(root, name)
        return name if os.path.exists(p) else None
    for d in DIRS:
        if os.path.exists(os.path.join(root, d, name)):
            return d + "/" + name
    return None
text = open(doc, encoding="utf-8").read()
cache = {}
def lines(rel):
    if rel not in cache:
        cache[rel] = open(os.path.join(root, rel), encoding="utf-8").read().split("\n")
    return cache[rel]
# a citation: `file.rs:NN` or `file.rs:NN–MM`, then continuations `:NN` / `:NN–MM` in backticks
tok = re.compile(r"`(?:(?P<file>[A-Za-z0-9_./-]+\.(?:rs|py|sh|txt)):)?(?::)?(?P<a>\d+)(?:[–-](?P<b>\d+))?(?P<open>–)?`")
cur = None
seen = set()
n = 0
for ln_no, line in enumerate(text.split("\n"), 1):
    cur = None
    for m in re.finditer(r"`([^`]+)`", line):
        s = m.group(1)
        mm = re.fullmatch(r"(?:(?P<file>[A-Za-z0-9_./-]+\.rs):)?:?(?P<a>\d+)(?:[–-](?P<b>\d+))?–?", s)
        if not mm:
            continue
        if mm.group("file"):
            cur = resolve(mm.group("file"))
            if cur is None:
                print(f"?? doc line {ln_no}: cannot resolve {mm.group('file')}")
                continue
        elif not s.startswith(":"):
            continue
        if cur is None:
            print(f"?? doc line {ln_no}: continuation {s} without a file")
            continue
        a = int(mm.group("a")); b = int(mm.group("b") or a)
        key = (cur, a, b)
        if key in seen:
            continue
        seen.add(key); n += 1
        src = lines(cur)
        if b > len(src) or a < 1 or b < a:
            print(f"!! doc line {ln_no}: {cur}:{a}-{b} out of range")
            continue
        short = cur.replace("crypto/rsa/src/", "").replace("crypto/", "")
        if full:
            for i in range(a, b + 1):
                print(f"{short}:{i}: {src[i-1].strip()[:150]}")
            print()
        else:
            first = src[a-1].strip()[:105]
            last = "" if b == a else "  ...  " + src[b-1].strip()[:60]
            print(f"{short}:{a}{'' if b == a else '-' + str(b)}: {first}{last}")
print(f"{n} distinct citations")
