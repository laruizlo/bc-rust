# `audit/` — tooling for the `bouncycastle-rsa` audit

Not part of the published crates and not a workspace member. Nothing here changes a line or a
visibility upstream. Baseline: `bcgit/bc-rust`, `feature/rsa-sig`, `30cbbab`; the 27 files the
audit speaks about are pinned in `baseline.sha256` and the harness refuses to build if one
differs.

This is the first pass's tree (baseline `b7e46cb`, kept as the project documents
`claude/rsa-wp0-audit-*`), ported in plan WP14.3 to the code as it is after the upstream
response. The plan it serves is the project document `claude/rsa-formal-audit-plan.md` (v3.0);
session state is in `claude/00-start-here-rsa-audit.md`; what was run with this tree is in
`claude/rsa-wp14-report.md` (WP14.1 to 14.3) and `claude/rsa-wp14-report-2.md` (WP14.4, the
verification of each fix).

## Layout

| Path | What it is |
|---|---|
| `baseline.sha256` | SHA-256 of the 27 audited source files (`crypto/rsa/src/*.rs`, `ec::{nat, montgomery}`, `utils::{ct, secret}`) at the pin |
| `ref/rsa_ref.py` | Reference model. Sections 1–9, the specification layer: one function per Rust function, computing the specified value with Python integers; a call the specification does not define raises `ContractError`. Section 10, the crate layer: what the Rust API answers where the specification is silent (constructor rules I1, the length rules of `*_from_hash` E11, the result check C7, `fill_bytes` K16) |
| `ref/selftest.py` | The model's known answers: RFC text, Wycheproof, NIST ACVP samples, and for the crate layer arithmetic written out independently. Must pass before the model judges anything |
| `ref/selftest_openssl.py` | The model against OpenSSL (PyPI `cryptography`); optional |
| `ref/gen_cases.py` | Differential run: writes cases, runs `diff_runner`, judges each result against the model, then alters a sample of results and checks that the judge refuses each (a judge that cannot fail proves nothing) |
| `ref/make_short_modulus_probe.py` | Generates `harness/tests/data/short_modulus.rs`, the first pass's data for finding F-02; the key it describes is refused now, and the probe asserts that |
| `ref/pss_interop.py` | Finding F-02, row (d) of plan WP14.4: RSASSA-PSS both ways against the model and OpenSSL at full-length moduli, the least and the greatest a size admits among them. The crate signs under fixed salts (the signing role with an RNG that holds the salt; `sign_from_hash_with_salt`) and each signature must be the model's byte for byte and verify under both; OpenSSL and the model sign and the crate must verify. Altered signatures, messages and parameter sets must be refused on each side |
| `ref/limb_order_check.py` | Finding F-05, row 3: one byte stream through the crate's key generation and through the model under three readings of `fill_random`; the key must be the documented reading's and no other's |
| `harness/` | Rust crate that compiles `crypto/rsa/src/*.rs` by path, with probes onto private functions |
| `harness/src/bin/diff_runner.rs` | Runs differential cases; a panic is a result line, not the end of the run |
| `harness/src/bin/ct_memcheck.rs`, `harness/check_ct_memcheck.sh`, `harness/judge_memcheck.py` | Secret-independence under Valgrind memcheck: the constructors, the kernel, and whole operations through the public API, at RSA-2048 by default and at every signing size with `SIZES=` |
| `harness/declassified.txt` | The declassification register: the lines where a secret-derived bit decides control flow by design, each with its argument or marked open. Whole-operation memcheck modes are judged against it |
| `harness/show_ct_instructions.sh`, `harness/ct_instructions.py` | Which conditional jumps, conditional moves and setcc the binary holds in the machine functions that build a Montgomery context and run the CRT, by source line (finding F-01, row (c)) |
| `harness/tests/probes.rs` | Behaviours the audit documents state, pinned by tests (debug and release). The first pass's probes of answered concerns are now regression tests of the answers. Added in WP14.4: what an error leaves in a signing role's output buffer, and where "an error, never a panic" ends (a caller's own `PssParams` past the documented salt bound; map flag 13, open) |
| `harness/compile_checks/`, `harness/check_compile.sh` | Facts that are compile errors, each family with a control that compiles: the verify-only sizes, findings F-04 and F-06, the rest of M10's inventory (`m10`), a foreign `PssParams` (`flag13`), the forms in which the language writes a struct value (`lang`, no crate code: the premise of the search `i1`), SHA-1 signing. Programs are built, not checked: a `const` assertion fires at instantiation |
| `vectors/inventory.py` | Which Wycheproof, bc-test-data and ACVP files exist and which the crate's suite loads |
| `wp11_lines.sh` | Prints every source line the review, the plan's new obligations, the first pass's register, the proof of I1 and the report's part 2 cite, old place beside new, and checks each row against a piece of its text |
| `tools/fn_diff.py` | Function-level diff of Rust sources between two git revisions, comments and assertion statements dropped: what plan WP14.1 uses to confirm which kernel functions are unchanged since the first pass |
| `tools/listed_searches.py`, `tools/rust_items.py` | Listed searches over the source, each ending with a control (the same search on copies of the source with one edit, which it must report): `i1`, every mention of a key type classified by the form it is written in, so where a key value is constructed, which functions return one, that no field is written from outside, that no macro writes code and the size traits are sealed (finding F-02, row (e); the premises of the proof of I1); `roles`, every role impl with its bound on the size and every call of the raw primitives (F-04, row (b)); `m10`, every function with const generic parameters, whether it is public, the relation between its widths and where it is asserted (F-06, row (b)) |
| `tools/mir_sites.py` | The first premise of the proof of I1 from the compiler: builds the crate's MIR (`rustc --emit=mir`, stable; dev profile) and lists every aggregate of the six key types with the function it stands in, a derive's expansion included; compares with a table; control: eight ways of writing a key that compile, each on a copy of the workspace, each reported |
| `tools/test_summary.py`, `tools/q.sh` | A `cargo test` log as one line per test binary and totals; a queue that runs long commands one after another with a log and a status line each (a session's command limit is ten minutes) |
| `run_wp14.sh` | Re-runs the tree's own evidence (the model's self-test, upstream's unit tests inside the harness, probes, compile checks, the differential run, the cited lines, memcheck); its last line is the WP14.3 gate |
| `run_wp14_4.sh` | Plan WP14.4, rows F-02 to F-06: what each line of a row rests on, in release and debug builds, ending with one line per line of a row. Needs `PYDEPS` |
| `logs/wp14_4-<rustc version>/` | The logs of the WP14.4 runs the report's part 2 cites, one file a step and `summary.txt`, for rustc 1.97.0 and 1.88.0. `logs/` is ignored; these were added with `git add -f` |
| `f01-pin-check.sh` | Finding F-01 at the pin (WP14.4, row F-01 (b)): the second reviewer's memcheck probe pointed at upstream's fix, nine build settings, self-contained: `audit/f01-pin-check.sh <checkout> <work dir>`. The project document `claude/rsa-wp14-f01-pin-check.sh`, byte for byte |
| `pack.py` | Packs this tree into self-extracting text files, the form in which it is kept as the project documents `claude/rsa-wp14-audit-ref-*` and `claude/rsa-wp14-audit-harness-*` |

## Run

```
git clone https://github.com/C2SP/wycheproof ../wycheproof && git -C ../wycheproof checkout 65ca494727a52944c204441c860b039e6786b99b
git clone --depth 1 https://github.com/bcgit/bc-test-data ../bc-test-data
git clone --depth 1 --filter=blob:none --sparse https://github.com/usnistgov/ACVP-Server ../ACVP-Server
git -C ../ACVP-Server sparse-checkout set gen-val/json-files/{RSA-KeyGen-FIPS186-5,RSA-SigGen-FIPS186-5,RSA-SigVer-FIPS186-5,RSA-SigVer-FIPS186-2,RSA-SignaturePrimitive-2.0,RSA-DecryptionPrimitive-Sp800-56Br2,KAS-IFC-SSC-Sp800-56Br2,KTS-IFC-Sp800-56Br2,KAS-IFC-Sp800-56Br2,KDA-HKDF-Sp800-56Cr2}
mkdir -p ../specs/rfc      # rfc8017.txt and rfc5869.txt (rfc-editor.org, or Debian/Ubuntu `doc-rfc-*`)
audit/run_wp14.sh                                             # needs valgrind for its steps 7 and 8
PATH=<1.88.0>/bin:$PATH CARGO_TARGET_DIR=<dir> audit/run_wp14.sh   # the MSRV
SIZES="3072 4096 8192" audit/harness/check_ct_memcheck.sh     # the other signing sizes
PYDEPS=<pip --target dir with cryptography> audit/run_wp14_4.sh    # WP14.4, rows F-02 to F-06
python3 -I audit/tools/listed_searches.py                     # the three listed searches alone
python3 -I audit/tools/mir_sites.py                           # where a key is built, from the crate's MIR
```

The function-level confirmation of WP14.1, and the scoped mutation run of WP14.2 as the
repository's `CLAUDE.md` prescribes it (a copy of `.cargo/mutants.toml` without its
`examine_globs`, test data linked into `/tmp`):

```
python3 -I audit/tools/fn_diff.py . b7e46cb HEAD crypto/ec/src/nat.rs crypto/ec/src/montgomery.rs \
    crypto/utils/src/ct.rs crypto/utils/src/secret.rs crypto/rsa/src/modexp.rs crypto/rsa/src/rsa_core.rs \
    crypto/rsa/src/keygen.rs --quiet --map double_mod_n=double_mod_n_vartime pow2_mod=pow2_mod_vartime \
    new=for_public_modulus is_probable_prime=is_probable_prime_in_own_frame keygen_from_rng=keygen_in_own_frame
ln -s "$PWD/../wycheproof" /tmp/wycheproof; ln -s "$PWD/../bc-test-data" /tmp/bc-test-data
sed '/^# Examine only files/,/^]/d' .cargo/mutants.toml > /tmp/mutants-scoped.toml
cargo mutants -p bouncycastle-rsa --config /tmp/mutants-scoped.toml -f crypto/rsa/src/modexp.rs \
    -f crypto/rsa/src/rsa_core.rs --jobs 1 --timeout 300 --no-shuffle
```

## How the harness reaches private code

- `pub(crate)` items: the file is a `#[path]` module of the harness crate, as upstream's
  `dev_scripts/oaep_ct_harness` does. All 23 files are included under their own names, so their
  `crate::` paths resolve to each other and nothing is stubbed.
- Private `fn`s (`modexp.rs`, `keygen.rs`, `emsa_pkcs1_v1_5.rs`): `build.rs` copies the file to
  `OUT_DIR`, turning its leading `//!` lines into `//` lines (an included file may not open with
  inner doc comments) and checking that no other byte differs; `src/lib.rs` includes the copy
  inside a module with a `probe` child, which sees its parent's private items.
- Upstream's 53 unit tests are compiled inside the harness too and must pass there
  (`cargo test --lib`): a check that the harness compiles the same code.

## Reading a differential result

`match` — equal to the model. `MISMATCH` / `PANIC` — to be settled by hand: a finding or a model
error. `expected` — a documented debug assertion fired in a debug build (`mod_pow`'s
`base < modulus`, narrower than obligation M9). `observation` — the input is outside the model's
contract; the Rust result is listed, not judged: the modulus 1 for either constructor (N4), an
even modulus for `for_secret_modulus` (M12). The run ends with what the model predicted for the
response's operations by kind (released or refused, accepted or refused, which error), and with
the judge control.

## Reading a memcheck result

Each mode marks its secrets undefined and ends with a deliberately variable-time scan over those
same values. memcheck must report the scan, or the mode is `VOID` (its inputs were not undefined;
silence would prove nothing).

- `clean` — only the control scan was reported.
- `reported` — a conditional jump or address depends on a secret, and the script prints where.
  Expected of `ctx_public` alone: the variable-time constructor over an undefined modulus, a
  control on the code. No other mode may report the doubling chain.
- `declassified` — a whole operation in which every report is a line of `declassified.txt` whose
  argument is written (the outcome of the result check in `rsasp1` and in RSASVE recovery).
- `result-handling` — the whole OAEP decryption: memcheck reports what `rsaes_oaep.rs` does with
  the decoding's outcome and the recovered key's length after `decode_out` has returned them,
  and nothing in the CRT, the mask generation or the decoding. Not a clean bill: the reports
  are listed, and they are plan gap G16, for WP5 to argue or to have fixed.

A report is a register entry's only if every frame inside the entry's line lies in the entry's
`via` files: a branch somewhere under a call made on a registered line is not excused by it.
