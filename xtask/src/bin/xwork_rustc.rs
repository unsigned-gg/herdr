//! `xwork-rustc`: `RUSTC_WRAPPER` entry point for the xwork content-addressable cache.
#[path = "../xwork_cache.rs"]
#[allow(dead_code)]
mod xwork_cache;

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    xwork_cache::run_rustc_wrapper(&args)
}
