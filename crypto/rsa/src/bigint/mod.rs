//! Internal fixed-precision big-integer engine for RSA. Not a public API.
//!
//! # Invariants and conventions (binding for every module in this tree)
//!
//! - **Little-endian limb order.** `limbs[0]` is least significant. Big-endian byte
//!   order appears only at the encoding boundary (RFC 8017 I2OSP/OS2IP wire format).
//! - **Capacity as type, no runtime length.** A `Uint<LIMBS>` occupies all `LIMBS`
//!   limbs at all times; every loop runs `0..LIMBS` unconditionally. Timing may depend
//!   on capacity (a public, type-level property), never on the value held.
//! - **Carry/borrow conventions.** `adc` chains a carry in `{0, 1}`; `sbb` chains a
//!   borrow in `{0, Word::MAX}`: the borrow-out of a full subtraction chain is
//!   directly a `Condition`-style all-ones/all-zeros mask (e.g. it *is* the `lt`
//!   result, with no normalization step).
//! - **Constant-time policy.** No branches on secret data; no memory indexing by
//!   secret values; loop bounds from type-level constants or public lengths only; no
//!   `/` or `%` outside `const` contexts on public type-level numbers; shifts only by
//!   public amounts; secret-dependent decisions travel as masks (`Condition<Word>`),
//!   never `bool`, with `to_bool_var` reserved for genuine public decision points.
//! - **Vartime naming rule.** Any function whose timing may depend on *values* (not
//!   just type-level sizes or public lengths) carries a `_vartime` suffix and a
//!   rustdoc justification of why its inputs are public.
//! - **Secrets live in `Secret<...>`.** `Uint` itself is a plain `Copy` value type
//!   (like `mldsa::Polynomial`); anything secret is born inside `Secret<Uint<N>>` and
//!   populated in place. Do not let secret material sit in bare `Uint` temporaries.
//!
//! # Limitations
//!
//! Rust makes no hard guarantee that constant-time shapes survive every
//! optimizer/target combination (see also the notes in `bouncycastle_utils::ct`).
//! This layer uses the standard mask idioms, forbids `unsafe`, and treats disassembly
//! spot-checks as assurance, not proof. Cores without a constant-time multiplier
//! (e.g. Cortex-M0/M23) are not constant-time for *any* limb code.

// Submodules land one per work item: limb, uint, cmp, select, encoding.
pub(crate) mod cmp;
pub(crate) mod encoding;
pub(crate) mod limb;
pub(crate) mod select;
pub(crate) mod uint;

#[cfg(test)]
mod tests;
