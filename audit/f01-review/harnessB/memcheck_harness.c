/* Valgrind taint harness for finding F-01 (second review).
 *
 * Marks the SECRET modulus (and base/exp) as "undefined" via the memcheck client request, then
 * runs each entry point of libf01b.so.  Memcheck reports a conditional jump/move that depends on
 * the secret, with the function in the stack.  Modes:
 *   signcore : the real MontgomeryContext::<16>::new(p) -> mod_pow  (the audited path)
 *   control  : f01_control_vartime, an explicit branch on the secret (positive control: MUST report)
 *   ctsub    : the crate's branch-free sub_mod over the secret   (clean control: must NOT report)
 *
 * The modulus's low limb is kept DEFINED and odd/nonzero so new()'s odd/zero validity check is not
 * itself the thing reported; the report then lands in the doubling loop (pow2_mod).  Build without
 * optimising this file so the calls are real.
 */
#include <valgrind/memcheck.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern void f01_sign_core(const uint64_t *m, const uint64_t *base, const uint64_t *exp, uint64_t *out);
extern void f01_control_vartime(const uint64_t *m, uint64_t *out);
extern void f01_ct_subref(const uint64_t *a, const uint64_t *b, const uint64_t *m, uint64_t *out);

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "signcore";
    uint64_t m[16], base[16], exp[16], a[16], b[16], out[16];

    /* Concrete, valid starting values (odd modulus with both top bits set, base/exp < modulus). */
    for (int i = 0; i < 16; i++) { m[i] = 0x1111111111111111ull * (i + 1); base[i] = i + 1; exp[i] = 7 * i + 3; a[i] = i; b[i] = 2 * i; }
    m[0] |= 1;                       /* odd */
    m[15] |= 0xC000000000000000ull;  /* top two bits set: a plausible prime shape, base < modulus */
    base[15] &= 0x3fffffffffffffffull;
    a[15] &= 0x3fffffffffffffffull; b[15] &= 0x3fffffffffffffffull;

    /* Mark the secret as undefined.  Keep limb 0 defined so the odd/zero validity check is clean;
     * everything the reduction actually branches on (the high limbs) is secret. */
    VALGRIND_MAKE_MEM_UNDEFINED(&m[1], 15 * sizeof(uint64_t));

    if (strcmp(mode, "signcore") == 0) {
        VALGRIND_MAKE_MEM_UNDEFINED(base, sizeof base);
        f01_sign_core(m, base, exp, out);
    } else if (strcmp(mode, "control") == 0) {
        f01_control_vartime(m, out);
    } else if (strcmp(mode, "ctsub") == 0) {
        VALGRIND_MAKE_MEM_UNDEFINED(a, sizeof a);
        VALGRIND_MAKE_MEM_UNDEFINED(b, sizeof b);
        f01_ct_subref(a, b, m, out);
    } else {
        fprintf(stderr, "usage: %s signcore|control|ctsub\n", argv[0]);
        return 2;
    }
    /* Make the result defined so printing it is not itself a report. */
    VALGRIND_MAKE_MEM_DEFINED(out, sizeof out);
    uint64_t acc = 0;
    for (int i = 0; i < 16; i++) acc ^= out[i];
    printf("%s done (digest %016llx)\n", mode, (unsigned long long)acc);
    return 0;
}
