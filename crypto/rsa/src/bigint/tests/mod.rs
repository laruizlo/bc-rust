//! Unit tests for the private bigint engine, one file per implementation module.
//!
//! These live inside `src/` (not the external `tests/` directory) because the bigint
//! tree is crate-private; compiling within the crate is what grants access. Run both
//! limb-width lanes:
//!
//! ```text
//! cargo test -p bouncycastle-rsa
//! RUSTFLAGS="--cfg force_limb32" cargo test -p bouncycastle-rsa
//! ```

mod limb;
