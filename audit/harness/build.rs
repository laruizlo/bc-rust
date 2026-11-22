//! Two jobs, both before any audited source is compiled.
//!
//! 1. Drift check. Every file this harness compiles from upstream is hashed and compared with
//!    `audit/baseline.sha256`. A mismatch stops the build: results obtained on drifted sources
//!    would be reported against the wrong baseline. Set `RSA_AUDIT_ALLOW_DRIFT=1` to build
//!    anyway (the mismatches are then printed as warnings). That gets past a comment's change,
//!    not past an API's: after the upstream response the tree had to be ported (plan WP14.3).
//!
//! 2. Probe copies. Three files have private functions the differential tests call directly
//!    (`modexp.rs`, `keygen.rs`, `emsa_pkcs1_v1_5.rs`). A parent module cannot see a child's
//!    private items, and `include!` rejects a file that opens with `//!` doc comments, so each
//!    is copied to OUT_DIR with the leading `//!` lines turned into plain `//` comments. No
//!    other byte changes, which this script verifies; `src/lib.rs` includes the copy inside a
//!    module that also holds the probe wrappers.

use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

const PROBED: [&str; 3] = ["modexp.rs", "keygen.rs", "emsa_pkcs1_v1_5.rs"];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let repo = Path::new(&manifest).join("../..");
    let baseline_path = repo.join("audit/baseline.sha256");
    println!("cargo:rerun-if-changed={}", baseline_path.display());
    println!("cargo:rerun-if-env-changed=RSA_AUDIT_ALLOW_DRIFT");
    let allow = env::var("RSA_AUDIT_ALLOW_DRIFT").is_ok();

    let baseline = fs::read_to_string(&baseline_path).expect("audit/baseline.sha256");
    let mut drift = Vec::new();
    for line in baseline.lines().filter(|l| !l.trim().is_empty()) {
        let (want, rel) = line.split_once("  ").expect("sha256sum format");
        let path = repo.join(rel);
        println!("cargo:rerun-if-changed={}", path.display());
        let got = hex(&Sha256::digest(fs::read(&path).unwrap_or_else(|_| panic!("missing {rel}"))));
        if got != want {
            drift.push(format!("{rel}: baseline {want}, found {got}"));
        }
    }
    if !drift.is_empty() {
        let msg = format!(
            "audited sources differ from audit/baseline.sha256 (plan section 2.1: re-open the \
             obligations that speak about these files):\n  {}",
            drift.join("\n  ")
        );
        if allow {
            for d in &drift {
                println!("cargo:warning=DRIFT {d}");
            }
        } else {
            panic!("{msg}");
        }
    }

    let out = env::var("OUT_DIR").unwrap();
    for name in PROBED {
        let src = fs::read_to_string(repo.join("crypto/rsa/src").join(name)).unwrap();
        let mut copy = String::with_capacity(src.len());
        let mut in_header = true;
        let mut changed = 0usize;
        for line in src.split_inclusive('\n') {
            if in_header && line.starts_with("//!") {
                copy.push_str("// ");
                copy.push_str(&line[3..]);
                changed += 1;
            } else {
                in_header = false;
                copy.push_str(line);
            }
        }
        // The copy differs from the source only in those header lines.
        let mut src_lines = src.split_inclusive('\n');
        let mut copy_lines = copy.split_inclusive('\n');
        for i in 0.. {
            match (src_lines.next(), copy_lines.next()) {
                (None, None) => break,
                (Some(a), Some(b)) if i < changed => {
                    assert!(a.starts_with("//!") && b.starts_with("// ") && a[3..] == b[3..]);
                }
                (Some(a), Some(b)) => assert_eq!(a, b, "{name}: body line {i} changed"),
                _ => panic!("{name}: line count changed"),
            }
        }
        assert!(changed > 0, "{name}: expected a `//!` header");
        fs::write(Path::new(&out).join(name), copy).unwrap();
    }
}
