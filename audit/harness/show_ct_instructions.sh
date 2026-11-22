#!/usr/bin/env bash
# Binary-level view of finding F-01's fix (plan WP14.4, F-01 row (c); observation O1): which
# conditional jumps, conditional moves and flag-to-byte instructions the line tables of the
# release-configuration binary attribute to the functions that build a Montgomery context --
# the constant-time chain (pow2_mod_ct, ct_shift_in_bit_mod, ct_select_array, and nat::sub
# under them) and, for contrast, the variable-time one (double_mod_n_vartime,
# for_public_modulus) -- per source line, and per machine function they were inlined into.
#
# What to read off it. A conditional jump on a line of the constant-time chain must be a loop
# counter (a `for` line); one on the selection or the subtraction would be the leak back. A
# conditional move there selects data under the mask; whether it selects a *value* or an
# *address* is not visible in a count, so the instructions themselves are printed with -v.
# The variable-time lines are expected to show jumps or moves: that is observation O1, the
# form depends on the compiler.
#
#   ./show_ct_instructions.sh [-v] [SYMBOL-SUBSTRING ...]     default: pow2_mod crt_exp_checked for_secret for_public
#   PATH=<toolchain>/bin:$PATH CARGO_TARGET_DIR=<dir> ./show_ct_instructions.sh
set -uo pipefail
cd "$(dirname "$0")"
cargo build --quiet --profile memcheck --bin ct_memcheck || exit 2
BIN=${CARGO_TARGET_DIR:-target}/memcheck/ct_memcheck
echo "toolchain: $(rustc --version); $(objdump --version | head -1); $(uname -m)"
objdump -d -l -C --no-show-raw-insn "$BIN" | python3 -I ct_instructions.py "$@"
