//! Finding F-01, second review — Harness A.
//!
//! 1. Faithfulness: the instrumented copy in `copy.rs` must behave identically to the snapshot's
//!    real `bouncycastle_rsa::modexp`. Checked by equality of `mont_n_prime` and of a full
//!    `mod_pow` (which is built on the context's R mod n and R^2 mod n, so a wrong context would
//!    diverge) over random inputs and the genuine RSA-2048 test vector.
//! 2. Leak: record the per-step branch decisions of `MontgomeryContext::new(p)` (the instrumented
//!    `double_mod_n`) for the genuine CRT prime `p` of the snapshot's own rsa_core test keypair,
//!    and emit the R^2-call decision bits plus the public modulus n. `recover.py` reconstructs p.

mod copy;

use bouncycastle_rsa::modexp as real;

// The genuine RSA-2048 CRT keypair from crypto/rsa/src/rsa_core.rs tests (two real ~1024-bit
// primes, e = 65537). p, q are [u64; 16]; n = p * q is [u64; 32].
const P: [u64; 16] = [
    0xfec673c1b07d4997, 0x98c9e3737faecc8b, 0x01369d6bebcfd19b, 0x8aadc1799d493a6e,
    0x958ca74fe2a455a1, 0x686e62c9e375661d, 0xbf73814b7bf6fe14, 0x791ffe2d364719e4,
    0xc82e25af581825a1, 0x716d239de20732c7, 0xdb517e266b0c15bc, 0xe92c721464fa1e50,
    0x683e7fcc3898a002, 0xc7f69cb8c57e630f, 0xc467ab3a006acdf7, 0xe189725eddf8ccb3,
];
const Q: [u64; 16] = [
    0x7b4cf8c928cc535f, 0x59f055409b91aa89, 0xcd0ba689661c56d5, 0xe4659bfb595039f4,
    0x751842ab04e21054, 0xe2c2655760ebb5fc, 0xb2f71094e48dc76b, 0x2efed995e680919d,
    0x83c35ffcfdb9ee9d, 0xfe4a5fdb9f28a01b, 0x0ebf4a61e23c7524, 0x8cc355a69e45d7e6,
    0x9589828fca436940, 0x4cd1bfe875cddd70, 0x203e0d5e8d4d3acb, 0x86278c27281306ec,
];

// A tiny deterministic xorshift, so the run is reproducible without external crates.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn limbs16(&mut self) -> [u64; 16] {
        let mut a = [0u64; 16];
        for l in a.iter_mut() {
            *l = self.next();
        }
        a
    }
}

fn hex_le_limbs(label: &str, a: &[u64]) -> String {
    // big-endian hex string of a little-endian limb array
    let mut s = String::new();
    for limb in a.iter().rev() {
        s.push_str(&format!("{limb:016x}"));
    }
    format!("{label}={s}")
}

fn main() {
    let mut fail = 0u32;

    // ---- Faithfulness check 1: mont_n_prime over random odd words. ----
    let mut rng = Rng(0x0F01_0017_C0FF_EE01);
    let mut mnp_ok = true;
    for _ in 0..50_000 {
        let n0 = rng.next() | 1;
        if copy::mont_n_prime(n0) != real::mont_n_prime(n0) {
            mnp_ok = false;
            break;
        }
    }
    println!(
        "{} faithful-mont_n_prime : copy::mont_n_prime == real::mont_n_prime over 50k odd words",
        if mnp_ok { "PASS" } else { "FAIL" }
    );
    fail += (!mnp_ok) as u32;

    // ---- Faithfulness check 2: full mod_pow at L=16 over random (base, exp) and both real primes. ----
    // mod_pow consumes the context's r_mod_n and r2_mod_n; if copy's MontgomeryContext::new
    // produced a wrong R mod n or R^2 mod n, these results would diverge from the real crate's.
    let mut mp_ok = true;
    'outer: for &modulus in &[P, Q] {
        let ctx_copy = copy::MontgomeryContext::<16>::new(&modulus).unwrap();
        let ctx_real = real::MontgomeryContext::<16>::new(&modulus).unwrap();
        for _ in 0..600 {
            let mut base = rng.limbs16();
            // reduce base below modulus so mod_pow's precondition holds: clear the top limb's
            // high bits (primes here have both top bits set, so this guarantees base < modulus).
            base[15] &= 0x3fff_ffff_ffff_ffff;
            let exp = rng.limbs16();
            let c = copy::mod_pow::<16, 32, 33>(&base, &exp, &ctx_copy);
            let r = real::mod_pow::<16, 32, 33>(&base, &exp, &ctx_real);
            if c != r {
                mp_ok = false;
                break 'outer;
            }
        }
    }
    println!(
        "{} faithful-mod_pow      : copy::mod_pow == real::mod_pow (L=16) over 1200 inputs on p and q",
        if mp_ok { "PASS" } else { "FAIL" }
    );
    fail += (!mp_ok) as u32;

    // ---- Leak: record the branch decisions MontgomeryContext::new(p) makes. ----
    // new() makes two pow2_mod calls: pow2_mod(64*16=1024, p) then pow2_mod(128*16=2048, p).
    // So the recording is 1024 + 2048 = 3072 bits; the R^2 call is the last 2048.
    copy::record_start();
    let _ = copy::MontgomeryContext::<16>::new(&P).unwrap();
    let bits_p = copy::record_take();

    copy::record_start();
    let _ = copy::MontgomeryContext::<16>::new(&Q).unwrap();
    let bits_q = copy::record_take();

    let expect = 64 * 16 + 128 * 16;
    let count_ok = bits_p.len() == expect && bits_q.len() == expect;
    println!(
        "{} branch-count          : new(p)/new(q) each select {} times (1024 for R + 2048 for R^2)",
        if count_ok { "PASS" } else { "FAIL" },
        expect
    );
    fail += (!count_ok) as u32;

    // Emit what an observer of those decisions sees, for recover.py: the R^2 slice (last 2048),
    // the public modulus n = p*q, and the true primes so the script can self-check.
    let r2_p: String = bits_p[64 * 16..].iter().map(|b| (b + b'0') as char).collect();
    let r2_q: String = bits_q[64 * 16..].iter().map(|b| (b + b'0') as char).collect();
    // n = p*q at 32 limbs, exactly as size.rs modulus_from_primes computes it.
    let n = bouncycastle_ec::montgomery::widening_mul::<16, 32>(&P, &Q);

    use std::io::Write;
    let mut f = std::fs::File::create("recover_input.txt").expect("write recover_input.txt");
    writeln!(f, "{}", hex_le_limbs("n", &n)).unwrap();
    writeln!(f, "{}", hex_le_limbs("p", &P)).unwrap();
    writeln!(f, "{}", hex_le_limbs("q", &Q)).unwrap();
    writeln!(f, "bitlen=1024").unwrap();
    writeln!(f, "T=2048").unwrap();
    writeln!(f, "r2bits_p={r2_p}").unwrap();
    writeln!(f, "r2bits_q={r2_q}").unwrap();
    println!("INFO emitted             : recover_input.txt (n, p, q, and the R^2 decision bits of new(p)/new(q))");

    if fail == 0 {
        println!("HARNESS-A-ALL-PASS");
    } else {
        println!("HARNESS-A-FAIL ({fail} check(s))");
        std::process::exit(1);
    }
}
