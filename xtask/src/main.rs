//! `herdr` Glaeda-accelerated `xtask` & `xwork` runner (`cargo xtask <command>`).

mod loadout;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

const DEFAULT_JOBS: &str = "2";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn jobs() -> String {
    env::var("JOBS")
        .or_else(|_| env::var("CARGO_BUILD_JOBS"))
        .unwrap_or_else(|_| DEFAULT_JOBS.to_owned())
}

fn run_cmd(root: &Path, program: &str, args: &[&str]) -> bool {
    eprintln!("+ {program} {}", args.join(" "));
    Command::new(program)
        .current_dir(root)
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn worktree_fingerprint(root: &Path) -> u64 {
    let spawn_git = |args: &[&str]| {
        Command::new("git")
            .current_dir(root)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
    };
    let s_child = spawn_git(&[
        "status",
        "--porcelain=v2",
        "--branch",
        "--untracked-files=all",
    ]);
    let d_child = spawn_git(&["diff", "HEAD"]);
    let mut combined = Vec::new();
    if let Ok(c) = s_child
        && let Ok(out) = c.wait_with_output()
    {
        combined.extend_from_slice(&out.stdout);
    }
    if let Ok(c) = d_child
        && let Ok(out) = c.wait_with_output()
    {
        combined.extend_from_slice(&out.stdout);
    }
    fnv1a_64(&combined)
}

fn memfs_xwork_state_path() -> PathBuf {
    let mem_root = Path::new("/Volumes/CortexMemFS/xwork");
    if mem_root.is_dir() {
        return mem_root.join("herdr.xwork-state");
    }
    PathBuf::from("/tmp/herdr.xwork-state")
}

fn toolchain_check(root: &Path) -> ExitCode {
    for req in ["rust-toolchain.toml", "clippy.toml", "Cargo.toml"] {
        if !root.join(req).is_file() {
            eprintln!("toolchain-check: missing {req}");
            return ExitCode::from(1);
        }
    }
    println!("toolchain-check: ok");
    ExitCode::SUCCESS
}

fn shed_hygiene(root: &Path) -> ExitCode {
    let shed_toml = root.join("vendor/rust-shed/Cargo.toml");
    if !shed_toml.is_file() {
        eprintln!("shed-hygiene: missing vendor/rust-shed/Cargo.toml");
        return ExitCode::from(1);
    }
    let root_toml = root.join("Cargo.toml");
    let Ok(src) = fs::read_to_string(&root_toml) else {
        eprintln!("shed-hygiene: cannot read Cargo.toml");
        return ExitCode::from(1);
    };
    if !src.contains("\"vendor/rust-shed\"") || !src.contains("rust-shed =") {
        eprintln!("shed-hygiene: Cargo.toml must wire vendor/rust-shed in workspace and dependencies");
        return ExitCode::from(1);
    }
    println!("shed-hygiene: ok (vendor/rust-shed wired in herdr)");
    ExitCode::SUCCESS
}

fn hygiene(root: &Path) -> ExitCode {
    for step in [toolchain_check, shed_hygiene] {
        if step(root) != ExitCode::SUCCESS {
            return ExitCode::from(1);
        }
    }
    loadout::verify_loadout_alpha(root)
}

fn fmt(root: &Path, check_only: bool) -> ExitCode {
    let args: &[&str] = if check_only {
        &["fmt", "--all", "--", "--check"]
    } else {
        &["fmt", "--all"]
    };
    if run_cmd(root, "cargo", args) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn smoke(root: &Path) -> ExitCode {
    let j = jobs();
    if run_cmd(
        root,
        "cargo",
        &["test", "-p", "rust-shed", "--all-features", "--lib", "-j", &j],
    ) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn xwork(root: &Path, args: &[String]) -> ExitCode {
    let fresh = args.iter().any(|a| a == "--fresh" || a == "--no-cache");
    let fast = args.iter().any(|a| a == "--fast");
    let fp = worktree_fingerprint(root);
    let expected = format!("{fp:016x}");
    let mem_path = memfs_xwork_state_path();
    let state_path = root.join("target/.xwork-state");

    if !fresh
        && (fs::read_to_string(&mem_path).is_ok_and(|s| s.trim() == expected)
            || fs::read_to_string(&state_path).is_ok_and(|s| s.trim() == expected))
    {
        println!(
            "xwork: worktree {expected} already verified in cortex-memfs (--fresh to force)"
        );
        return ExitCode::SUCCESS;
    }

    if hygiene(root) != ExitCode::SUCCESS {
        return ExitCode::from(1);
    }
    if !fast && smoke(root) != ExitCode::SUCCESS {
        return ExitCode::from(1);
    }

    let _ = fs::write(&mem_path, format!("{expected}\n"));
    let _ = fs::create_dir_all(root.join("target"));
    let _ = fs::write(&state_path, format!("{expected}\n"));
    println!("xwork: verified worktree {expected} (persisted to cortex-memfs)");
    ExitCode::SUCCESS
}

fn bench(root: &Path) -> ExitCode {
    let stages: &[(&str, fn(&Path) -> ExitCode)] = &[
        ("toolchain-check", toolchain_check),
        ("shed-hygiene", shed_hygiene),
        ("hygiene-all", hygiene),
    ];
    println!("=== herdr Glaeda xwork in-process benchmark ===");
    for (name, func) in stages {
        let t0 = Instant::now();
        let rc = func(root);
        let us = t0.elapsed().as_micros();
        println!("  {name:<20} : {us:>6} us (status={rc:?})");
        if rc != ExitCode::SUCCESS {
            return rc;
        }
    }
    let t_fp = Instant::now();
    let fp = worktree_fingerprint(root);
    let fp_ms = t_fp.elapsed().as_secs_f64() * 1000.0;
    println!("  worktree_fingerprint : {fp_ms:>6.2} ms (fp={fp:016x})");
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let root = repo_root();
    match args.first().map(String::as_str) {
        Some("xwork") => xwork(&root, &args[1..]),
        Some("bench") => bench(&root),
        Some("hygiene") => hygiene(&root),
        Some("toolchain-check") => toolchain_check(&root),
        Some("shed-hygiene") => shed_hygiene(&root),
        Some("loadout") | Some("loadout-check") => loadout::run(&root, &args[1..]),
        Some("fmt") => fmt(&root, args.iter().any(|a| a == "--check")),
        Some("fmt-check") => fmt(&root, true),
        Some("smoke") => smoke(&root),
        other => {
            if let Some(name) = other {
                eprintln!("xtask: unknown command {name:?}");
            }
            eprintln!(
                "usage: cargo xtask <xwork|bench|hygiene|toolchain-check|shed-hygiene|loadout|fmt|fmt-check|smoke>"
            );
            ExitCode::from(2)
        }
    }
}
