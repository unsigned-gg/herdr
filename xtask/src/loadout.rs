//! `cargo xtask loadout` for `unsigned-gg/herdr` (Loadout Alpha: Line-Rate Edge).

use std::fs;
use std::path::Path;
use std::process::ExitCode;

pub fn verify_loadout_alpha(root: &Path) -> ExitCode {
    println!("\n=== Verifying Battery Pack Compatibility (herdr: Loadout Alpha) ===");
    let mut all_ok = true;

    let rust_shed = root.join("vendor/rust-shed");
    let classifier = root.join("vendor/classifier");
    let spiffe_svid = root.join("vendor/spiffe-svid");

    if !rust_shed.is_dir() {
        eprintln!(
            "  [FAIL] vendor/rust-shed not found at {}",
            rust_shed.display()
        );
        all_ok = false;
    } else if let Ok(toml) = fs::read_to_string(rust_shed.join("Cargo.toml")) {
        if toml.contains("auth0 =") {
            println!("  [OK] vendor/rust-shed present with auth0 feature");
        } else {
            eprintln!("  [WARN] vendor/rust-shed missing auth0 feature");
        }
    }

    if !classifier.is_dir() {
        eprintln!(
            "  [FAIL] vendor/classifier not found at {}",
            classifier.display()
        );
        all_ok = false;
    } else {
        println!("  [OK] vendor/classifier present");
    }

    if !spiffe_svid.is_dir() {
        eprintln!(
            "  [FAIL] vendor/spiffe-svid not found at {}",
            spiffe_svid.display()
        );
        all_ok = false;
    } else {
        println!("  [OK] vendor/spiffe-svid present");
    }

    if all_ok {
        println!("  [OK] Loadout Alpha (\"Line-Rate Edge\") passed validation.\n");
        ExitCode::SUCCESS
    } else {
        eprintln!("  [FAIL] Loadout Alpha validation failed.\n");
        ExitCode::FAILURE
    }
}

pub fn run(root: &Path, args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        None | Some("verify") | Some("check") | Some("alpha") => verify_loadout_alpha(root),
        Some(other) => {
            eprintln!("unknown loadout subcommand {other:?}; usage: cargo xtask loadout [verify]");
            ExitCode::from(2)
        }
    }
}
