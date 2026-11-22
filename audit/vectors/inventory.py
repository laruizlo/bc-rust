#!/usr/bin/env python3
"""Vector inventory for crypto/rsa (audit plan WP0; taken again at the pin in WP14.1).

    python3 -I audit/vectors/inventory.py --repo . --wycheproof DIR --bc-test-data DIR --acvp DIR

Lists every RSA vector file available in Wycheproof, bc-test-data and NIST's ACVP-Server sample
set, and whether the crate's test suite loads it. "Loaded" is decided from the test sources:
a file name that appears as a string literal, or that the OAEP suite builds from its stem table.
"""
import argparse
import json
import os
import re
import subprocess


def git_head(d):
    try:
        return subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()[:12]
    except Exception:
        return "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--wycheproof", required=True)
    ap.add_argument("--bc-test-data", required=True)
    ap.add_argument("--acvp", required=True)
    a = ap.parse_args()

    tests_dir = os.path.join(a.repo, "crypto/rsa/tests")
    used = {}                                   # vector file name -> [test files]
    for tf in sorted(os.listdir(tests_dir)):
        src = open(os.path.join(tests_dir, tf)).read()
        names = set(re.findall(r'"((?:acvp/)?[A-Za-z0-9_.-]+\.json)"', src))
        if 'format!("rsa_oaep_{stem}_test.json")' in src:
            names |= {f"rsa_oaep_{s}_test.json" for s in re.findall(r'\("(\d{4}_sha[0-9a-z_]+)",\s*\d+,\s*\d+\)', src)}
        for m in re.finditer(r'format!\("(?:openssl/)?(openssl_rsasve_)\{[a-z_]*\}(\.json)"', src):
            names |= {f"{m.group(1)}{bits}{m.group(2)}" for bits in (2048, 3072, 4096, 8192)}
        for n in names:
            used.setdefault(os.path.basename(n), []).append(tf)

    wdir = os.path.join(a.wycheproof, "testvectors_v1")
    wfiles = sorted(f for f in os.listdir(wdir) if f.startswith("rsa"))
    print(f"### Wycheproof (C2SP/wycheproof @ {git_head(a.wycheproof)}), `testvectors_v1/rsa*`: {len(wfiles)} files\n")
    print("| File | Algorithm | Tests | Loaded by | If not: why |")
    print("|---|---|---|---|---|")
    n_used = n_tests_used = n_tests = 0
    for f in wfiles:
        j = json.load(open(os.path.join(wdir, f)))
        nt = j["numberOfTests"]
        n_tests += nt
        by = used.get(f)
        why = ""
        if not by:
            if "three_primes" in f:
                why = "multi-prime RSA: no key form for it in the crate"
            elif re.fullmatch(r"rsa_pkcs1_\d+_test\.json", f):
                why = "RSAES-PKCS1-v1_5 decryption: scheme deliberately absent"
            elif "sha3_" in f:
                why = "PKCS #1 v1.5 with SHA-3: admitted by the type bounds, no suite"
            elif "sha512_224" in f or "sha512_256" in f or "sha224" in f:
                why = "truncated SHA-2 / SHA-224 pairing: admitted by the type bounds, no suite"
            elif f.startswith("rsa_pss_misc"):
                why = "150 parameter combinations (hash, MGF1 hash, salt length): not run"
            elif "_params" in f:
                why = "same signatures with RSASSA-PSS-params in the key encoding: not run"
            elif "sha1" in f:
                why = "SHA-1 pairing: admitted by the type bounds, no suite"
            elif f == "rsa_pss_4096_sha512_mgf1_32_test.json":
                why = "SHA-512 with a 32-byte salt (`Mgf1<SHA512, 32>`): admitted by the type bounds, no suite"
            elif "shake256" in f:
                why = "SHAKE256 at this size: admitted by the type bounds, no suite"
            else:
                why = "not run"
        else:
            n_used += 1
            n_tests_used += nt
        print(f"| `{f[:-10]}` | {j['algorithm']} | {nt} | {', '.join('`' + b[:-3] + '`' for b in sorted(set(by))) if by else '—'} | {why} |")
    print(f"\nLoaded: {n_used} of {len(wfiles)} files ({n_tests_used} of {n_tests} tests). A file named in a test is not "
          f"proof that every vector in it is run: `rsa_oaep_misc` is run only at sizes with a private key. (The 8192-bit signature files, sampled at the first pass, are run whole since 0c68586.)\n")
    missing = sorted(n for n in used if n.startswith("rsa") and n not in wfiles)
    if missing:
        print(f"Named in the tests but absent from this Wycheproof checkout: {missing}\n")

    bdir = os.path.join(a.bc_test_data, "crypto/rsa")
    print(f"### bc-test-data (bcgit/bc-test-data @ {git_head(a.bc_test_data)}), `crypto/rsa`\n")
    print("| File | Loaded by |")
    print("|---|---|")
    for root, _, files in sorted(os.walk(bdir)):
        for f in sorted(files):
            by = used.get(f)
            print(f"| `{os.path.relpath(os.path.join(root, f), bdir)}` | {', '.join('`' + b[:-3] + '`' for b in sorted(set(by))) if by else '— (not a vector file)' if not f.endswith('.json') else '—'} |")

    adir = os.path.join(a.acvp, "gen-val/json-files")
    in_suite = {"KAS-IFC-SSC-Sp800-56Br2", "RSA-DecryptionPrimitive-Sp800-56Br2"}
    print(f"\n### NIST ACVP-Server samples (usnistgov/ACVP-Server @ {git_head(a.acvp)}), `gen-val/json-files`\n")
    print("| Directory | Groups | Tests | In the crate's suite | Reference model self-test |")
    print("|---|---|---|---|---|")
    model = {"RSA-SigGen-FIPS186-5": "yes (51 of 96; SP 800-106 groups not modelled)", "RSA-SigVer-FIPS186-5": "yes (270)",
             "RSA-SigVer-FIPS186-2": "yes (360 of 540; ANS X9.31 not modelled)", "RSA-SignaturePrimitive-2.0": "yes (90)",
             "RSA-DecryptionPrimitive-Sp800-56Br2": "yes (90)", "RSA-KeyGen-FIPS186-5": "yes (15: key relations and A.1.1 criteria)",
             "KAS-IFC-SSC-Sp800-56Br2": "yes (20)", "KTS-IFC-Sp800-56Br2": "yes (20 of 40; associated data not modelled)",
             "KAS-IFC-Sp800-56Br2": "no (full KAS1/KAS2 with KDF and key confirmation)", "KDA-HKDF-Sp800-56Cr2": "no (fixed-info encoding is WP12's)"}
    for d in sorted(os.listdir(adir)):
        p = os.path.join(adir, d, "internalProjection.json")
        if not os.path.exists(p):
            continue
        j = json.load(open(p))
        nt = sum(len(g["tests"]) for g in j["testGroups"])
        print(f"| `{d}` | {len(j['testGroups'])} | {nt} | {'yes, as a copy in bc-test-data' if d in in_suite else 'no'} | {model.get(d, 'no')} |")


if __name__ == "__main__":
    main()
