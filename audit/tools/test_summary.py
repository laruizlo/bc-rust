#!/usr/bin/env python3
"""Summarize a `cargo test` log: one line per test binary and the totals.
usage: test_summary.py <log> [--brief]"""
import re, sys
log = open(sys.argv[1], errors="replace").read().splitlines()
brief = "--brief" in sys.argv
cur, rows = None, []
for line in log:
    m = re.match(r"\s+Running (\S+)(?: \((\S+)\))?", line)
    if m:
        cur = m.group(1); continue
    m = re.match(r"\s+Doc-tests (\S+)", line)
    if m:
        cur = "doc-tests " + m.group(1); continue
    m = re.match(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([\d.]+)s", line)
    if m:
        rows.append((cur, m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(6)), float(m.group(7))))
tot = [sum(r[i] for r in rows) for i in (2, 3, 4, 5)]
secs = sum(r[6] for r in rows)
if not brief:
    for r in rows:
        print(f"{r[2]:5d} passed {r[3]:3d} failed {r[4]:3d} ignored {r[5]:4d} filtered {r[6]:8.2f}s  {r[1]:6s} {r[0]}")
print(f"TOTAL {len(rows)} result lines: {tot[0]} passed, {tot[1]} failed, {tot[2]} ignored, {tot[3]} filtered out; test time {secs:.1f}s")
fails = [l for l in log if re.match(r"test .* \.\.\. FAILED", l) or "panicked at" in l]
for f in fails[:20]:
    print("  !", f[:200])
