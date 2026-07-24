# CLAUDE.md — `bouncycastle-rsa`

Guidance for Claude Code when working in `crypto/rsa/`. This inherits everything in the
repo-root `CLAUDE.md`, `QUALITY_AND_STYLE.md`, and `INTRODUCTION.md`; the notes here are
the RSA-specific additions. When the two conflict, the root rules win.

## Status

**Not yet implemented.** This crate is being built from scratch as a stacked branch chain
based on `release/0.1.2alpha` (the most up-to-date branch — 35 commits ahead of `main`).

Implementation is driven by phase specs in `specs/` (currently
`specs/phase-1-bigint-representation.md`, the approved phase-1 plan, with its
compile-verified prototype in `specs/phase-1-verified-prototype.md`). The spec's
**5 phases** map onto the **4-branch chain** like so:

```
release/0.1.2alpha
 └─ luis/rsa/bigint     ① spec phases 1–3: bigint representation (limbs, Uint<LIMBS>, encoding,
     │                    CT predicates), then arithmetic (add/sub/mul/shift), then Montgomery
     │                    (params, reduction, exponentiation)
     └─ luis/rsa/core   ② spec phase 4: RSA key types, keygen (prime gen + CRT params),
         │                RSAEP/RSADP/RSASP1/RSAVP1, CRT private op, blinding
         └─ luis/rsa/schemes      ③ spec phase 5 (first half): OAEP (enc), PSS (sig), PKCS#1 v1.5
             └─ luis/rsa/integration  ④ spec phase 5 (second half): core-trait impls, factory,
                                        CLI, benches, mem_usage bench, docs
```

Each link builds on the previous and is meant to be reviewed on its own. Final merge targets
`release/0.1.2alpha` (RSA's true parent), not `main` — the two have diverged (`main` has 15
commits not in `release`), so let the team's normal `release → main` merge carry RSA forward.

## Design decisions

- **Bigint is a private module inside this crate** (decided — spec D1). The `bigint` tree lives
  at `src/bigint/` as `mod bigint;` with everything `pub(crate)` — bc-rust does not expose a
  big-int API. Consequences: unit tests are in-file `#[cfg(test)]` blocks (sanctioned for
  private code), and benches reach internals via a non-default `bench-internals` feature gating
  a `#[doc(hidden)] pub mod internals` re-export. It still lands and is reviewed independently
  (branch ①) before any RSA logic depends on it.
- **Still open — trait fit for encryption.** PSS / PKCS#1-sig map onto the existing
  `core::Signature` trait. RSA-OAEP encryption fits none of `Hash/KDF/MAC/KEM/Signature` —
  decide in link ③ whether to add a public-key-encryption trait to `core`, or model RSA-KEM
  onto the existing `KEM` trait.

## Non-negotiable house rules that bite hardest for RSA

- **No third-party runtime deps.** No `num-bigint`, no `crypto-bigint`, nothing. The bignum is
  written from scratch in this workspace. (Dev/bench deps like `criterion` are fine.)
- **`#![forbid(unsafe_code)]` and `#![forbid(missing_docs)]`** at every `lib.rs`. `#![no_std]`
  is *required* by QUALITY_AND_STYLE.md, but is currently blocked repo-wide by the `core`
  crate's `Vec`-removal TODO — so: prefer const-sized `[Limb; N]` over heap `Vec`, and never add
  new `Vec` where a const-generic width works, so this crate is `no_std`-ready the moment `core`
  unblocks it.
- **`SerializableState`.** Any algorithm with state exercised across multiple API calls (a
  `do_update()` / `do_final()` streaming API) must impl `SerializableState` so a user can pause
  to a cache and resume. Applies to any streaming RSA hash-input or multi-block flow we expose.
- **Constant-time on all secret-dependent paths.** Private-key modexp, CRT recombination, and
  OAEP/PKCS#1 decryption padding checks must not branch or index on secret data. Use blinding on
  the private operation. This is the single most important correctness/security property here —
  comment every place where constant-time behaviour is load-bearing.
- **Push errors to compile time.** Prefer `&[u8; N]` + const-generic modulus width over
  runtime length checks. `Result` only for truly-uncontrollable failures (RNG failure, caller-
  supplied malformed key). Run `./dev_scripts/quality_stats.sh` before/after — don't raise the
  unwrap / `Err()` counts.
- **`unwrap()` needs justification** — a preceding check that proves success, or an inline
  comment explaining infallibility.
- **No `init()` / `reset()`; `do_final` takes `self` by value.** Constructors set up state,
  consumption methods consume. Provide a one-shot static API in addition to any streaming one.
- **Sensitive types impl `core::Secret`** (and supertraits). Private exponent, primes `p`/`q`,
  CRT params `dP`/`dQ`/`qInv`, and any intermediate holding them are secrets — never raw byte
  arrays. They must zeroize on drop.

## Naming conventions (library-specific, from QUALITY_AND_STYLE.md)

- **`pk` / `sk`** for public key / secret (private) key — not `pub`/`priv` (`pub` is a keyword).
- **`LEN` = bytes, `SIZE` = bits.** e.g. a 2048-bit modulus → `MODULUS_SIZE = 2048`,
  `MODULUS_LEN = 256`. Use `SIZE` for security parameters, `LEN` for array sizing.
- **`do_*()`** names any function that is part of a stateful streaming API.
- Standard clippy naming otherwise.

## Spec correspondence

RSA follows **RFC 8017 (PKCS #1 v2.2)** for RSAEP/RSADP, OAEP (§7.1), PSS (§8.1), and
PKCS#1 v1.5 (§8.2 / §7.2). Prime generation and key validation follow **FIPS 186-5** /
**SP 800-56B**. Comment code line-by-line against the spec section it mirrors; call out and
justify any deliberate deviation. Bar: "would 6-months-from-now me need >10 min to re-understand?"

## The per-primitive checklist (owed before ⑤ is done)

Every primitive in this workspace must ship all of:

- Tests driven through `core-test-framework` (trait conformance + error-condition coverage) —
  don't duplicate the canonical trait tests per-implementation. Live in `src/tests`. Every
  public-interface behaviour must be constrained by a test (treat future maintainers as
  malicious). Behaviour-critical *private* functions get in-file `#[cfg(test)] mod tests`.
- **Known-answer vectors against both the bc-test-data repo and wycheproof** — in addition to
  the RFC 8017 / FIPS vectors. Wycheproof's RSA/OAEP/PSS suites cover malformed-padding and
  edge cases that catch constant-time / validation bugs.
- Criterion benches in `benches/` (`[[bench]]`, `harness = false`). Benchmark each variant with
  a distinct perf profile *separately* (e.g. CRT vs non-CRT private op, pre-expanded keys), but
  do **not** write separate benches for one-shot vs streaming of the same underlying impl.
- A `mem_usage_benches/` harness — RSA's stack usage is non-trivial and must be characterized.
- A streaming stdin→stdout CLI subcommand in `cli/src/*_cmd.rs`, registered in `cli/src/main.rs`.
- Registration in the matching `factory` enum once the trait fit is decided.
- Crate docs with the required sections: **Usage Examples**, **Memory Usage** (stack table),
  and **Security Considerations**.

## Build / test

```
cargo build -p bouncycastle-rsa
cargo test  -p bouncycastle-rsa
cargo bench -p bouncycastle-rsa
cargo mutants        # surviving mutants must be investigated (config in .cargo/mutants.toml)
```

The workspace `members = ["crypto/*", ...]` glob auto-registers this crate once it has a
`Cargo.toml` + `src/lib.rs`.
