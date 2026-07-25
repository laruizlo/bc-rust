//! Unit tests for the private bigint engine, one file per implementation module.
//!
//! Layout note: these files live under `tests/bigint/` so `quality_stats.sh`
//! counts them as test code (its assumption is "test code is all in the tests
//! folder"), but they are NOT cargo integration tests. Cargo only auto-discovers
//! top-level `tests/*.rs` files; this subdirectory is instead mounted into the
//! crate by `src/bigint/mod.rs` via a `#[path]` attribute, so the tests compile
//! as crate-internal unit tests with access to the private bigint modules.
//!
//! Run both limb-width lanes:
//!
//! ```text
//! cargo test -p bouncycastle-rsa
//! RUSTFLAGS="--cfg force_limb32" cargo test -p bouncycastle-rsa
//! ```

mod cmp;
mod encoding;
mod limb;
mod select;
mod uint;
mod vectors;
