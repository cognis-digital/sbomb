// CLI entrypoint for the Rust port of sbomb.
//
//   cargo run -- <rootfs>   # scan a rootfs, print CycloneDX JSON
//   exit 1 when vulnerabilities are found (CI gate), 2 on a bad path.
use std::path::PathBuf;
use std::process::exit;

use sbomb::{build_cyclonedx, match_vulns, scan_rootfs};

fn main() {
    let target = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());
    let mut comps = match scan_rootfs(&PathBuf::from(&target)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            exit(2);
        }
    };
    let total = match_vulns(&mut comps);
    println!("{}", build_cyclonedx(&comps));
    if total > 0 {
        exit(1);
    }
}
