//! RSA (RFC 8017 / PKCS #1 v2.2) — under construction.
//!
//! This crate currently contains only the private big-integer representation layer
//! (phase 1 of the implementation plan in `crypto/rsa/specs/`). There is no public
//! RSA API yet; the key types, RSAEP/RSADP and the padding schemes arrive in later
//! phases.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod bigint;

/// Internal, unstable re-exports for this crate's benchmarks only.
///
/// Criterion benches are external crates and cannot see `pub(crate)` items, so the
/// non-default `bench-internals` feature gates this doc-hidden window into the bigint
/// engine. Nothing here is public API: items may change or vanish without notice, and
/// the feature is never enabled by in-tree dependents.
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub mod internals {
    // Re-exports are added as the bigint modules land (limb, uint, cmp, select, encoding).
}
