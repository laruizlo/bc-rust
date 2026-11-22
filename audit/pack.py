#!/usr/bin/env python3
"""Packs the audit/ tree into self-extracting text files, small enough to be kept as project
documents (the audit's only store between sessions until the tree lives in a repository).

    python3 audit/pack.py OUTDIR      # writes OUTDIR/rsa-wp14-audit-<group>-<k>.{sh,txt}

Two archives, so that a change in one half does not force the other to be stored again:
    ref       audit/ref and audit/vectors (the reference model and what feeds it)
    harness   everything else (the Rust harness, the scripts, the README)
Each archive is tar, xz, base64, cut into parts of at most 250 lines so that a tool that shows
a few hundred lines per call shows a whole part. Part 1 is a POSIX shell script that reads the
other parts from its own directory:

    for f in <dir>/*rsa-wp14-audit-*-1.sh; do sh "$f" <bc-rust checkout>; done

The archives are deterministic (sorted names, no times, no owners): packing an unchanged tree
gives the same files. Build products are left out (what audit/.gitignore names). The
extractor checks the SHA-256 of the archive, which covers every part.
"""
import base64
import hashlib
import io
import lzma
import os
import sys
import tarfile

SKIP_DIRS = {"target", "__pycache__", "logs", "examples"}
BASELINE = "30cbbab"
STEM = "rsa-wp14-audit"          # the first pass's archives are rsa-wp0-audit-*: left as they are
PART_LINES = 250
GROUPS = (("ref", ("ref/", "vectors/")), ("harness", None))

EXTRACTOR = r'''
import base64, hashlib, io, lzma, os, sys, tarfile
src, top = sys.argv[1], sys.argv[2]
if not os.path.isdir(os.path.join(top, "crypto", "rsa", "src")):
    sys.exit("not a bc-rust checkout: " + top)
lines = open(src, "rb").read().split(b"\n")
i = lines.index(b"#=====PAYLOAD=====")
_, want, parts = lines[i + 1].decode().split()
data = b"".join(lines[i + 2:])
for k in range(2, int(parts) + 1):
    part = src[:-len("-1.sh")] + "-%d.txt" % k
    if not os.path.isfile(part):
        sys.exit("missing part: " + part)
    data += b"".join(open(part, "rb").read().split())
raw = lzma.decompress(base64.b64decode(data))
if hashlib.sha256(raw).hexdigest() != want:
    sys.exit("the archive is damaged: SHA-256 differs from the one recorded in part 1")
n = 0
with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
    for m in tar:
        names = m.name.split("/")
        if not m.isfile() or names[0] != "audit" or ".." in names or m.name.startswith("/"):
            sys.exit("unexpected archive member: " + m.name)
        out = os.path.join(top, *names)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        open(out, "wb").write(tar.extractfile(m).read())
        os.chmod(out, m.mode)
        n += 1
print("%d files written under %s (archive SHA-256 %s)" % (n, os.path.join(top, "audit"), want[:16]))
'''
assert "'" not in EXTRACTOR


def tree(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
        for f in sorted(files):
            full = os.path.join(d, f)
            yield os.path.relpath(full, root).replace(os.sep, "/"), full


def main():
    outdir = sys.argv[1]
    root = os.path.dirname(os.path.abspath(__file__))
    files = sorted(tree(root))
    claimed = tuple(p for _, prefixes in GROUPS if prefixes for p in prefixes)
    os.makedirs(outdir, exist_ok=True)
    for group, prefixes in GROUPS:
        mine = [(r, f) for r, f in files if (r.startswith(prefixes) if prefixes else not r.startswith(claimed))]
        buf, listing = io.BytesIO(), []
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for rel, full in mine:
                data = open(full, "rb").read()
                info = tarfile.TarInfo("audit/" + rel)
                info.size = len(data)
                info.mode = 0o755 if os.access(full, os.X_OK) else 0o644
                tar.addfile(info, io.BytesIO(data))
                listing.append(f"#   {hashlib.sha256(data).hexdigest()[:16]}  {data.count(b'\n'):5d} lines  audit/{rel}")
        raw = buf.getvalue()
        payload = base64.encodebytes(lzma.compress(raw, format=lzma.FORMAT_XZ, preset=9 | lzma.PRESET_EXTREME)).split(b"\n")[:-1]
        stem = f"{STEM}-{group}"
        head = [
            "#!/bin/sh",
            f"# bc-rust RSA audit: the audit/ tree, archive \"{group}\". Baseline {BASELINE}. {len(listing)} files.",
            f"# A shell script followed by a payload (tar, xz, base64) that continues in {stem}-2.txt ...",
            "# in the same directory, with or without a common prefix on the file names. To unpack:",
            f"#     sh {stem}-1.sh <bc-rust checkout>",
            "# It writes <checkout>/audit/... after checking the archive's SHA-256. Then read",
            "# audit/README.md. Made by audit/pack.py: edit the tree and re-pack, not these files.",
            "# Contents (first 16 hex digits of each file's SHA-256):",
        ] + listing + [f"exec python3 -I -c '{EXTRACTOR}' \"$0\" \"${{1:?usage: sh $0 <bc-rust checkout>}}\"",
                       "#=====PAYLOAD====="]
        head_lines = "\n".join(head).count("\n") + 2
        first = max(1, PART_LINES - head_lines)
        chunks = [payload[:first]] + [payload[i:i + PART_LINES] for i in range(first, len(payload), PART_LINES)]
        head.append(f"#sha256 {hashlib.sha256(raw).hexdigest()} {len(chunks)}")
        for k, chunk in enumerate(chunks, 1):
            name = os.path.join(outdir, f"{stem}-{k}." + ("sh" if k == 1 else "txt"))
            body = ("\n".join(head).encode() + b"\n" if k == 1 else b"") + b"\n".join(chunk) + b"\n"
            open(name, "wb").write(body)
            print(f"{name}: {body.count(b'\n')} lines, {len(body)} bytes")
        print(f"  archive {group}: {len(listing)} files, SHA-256 {hashlib.sha256(raw).hexdigest()[:16]}, {len(chunks)} parts")


if __name__ == "__main__":
    main()
