//! Content-addressable `RUSTC_WRAPPER` build cache (generic L1/L2 tiers).
//!
//! Adapted from `cerebral-work/vilicus` `xtask/src/xwork_cache.rs` (vilicus commit
//! 93287f59823149e4a62074b77c6b433b76cfe95b). Only the generic parts are present:
//! SHA-256 keying, rustc argv classification, and the local L1 (RAM) and L2 (disk)
//! stores. The L3 peer transport, deadline scorers, SHM headers, and benchmark
//! harness of the source file are deliberately not included.
//!
//! Uses only `std` and `rust-shed` (`serde`, `serde_json`).
//! - Hash: FIPS 180-4 SHA-256 with ASCII domain tags.
//! - L1 hot store: `$XWORK_CAS_L1_DIR`, else `/dev/shm/xwork-cas-v1`, else `/tmp/xwork-cas-v1`.
//! - L2 warm store: `$XWORK_CAS_L2_DIR`, else `~/.cache/herdr-xwork/cas/v1`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Instant, UNIX_EPOCH};

use rust_shed::serde::{Deserialize, Serialize};
use rust_shed::serde_json;

pub const DOMAIN_PLATFORM_V1: &[u8] = b"xwork-platform-v1\0";
pub const DOMAIN_CACHE_KEY_V1: &[u8] = b"xwork-cache-key-v1\0";

const HERMETIC_CRATE_TYPES: &[&str] = &["lib", "rlib", "rmeta", "proc-macro"];

const ENV_ALLOWLIST_EXACT: &[&str] = &[
    "CARGO_PKG_NAME",
    "CARGO_PKG_VERSION",
    "CARGO_PKG_AUTHORS",
    "CARGO_CRATE_NAME",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "TARGET",
    "PROFILE",
    "OPT_LEVEL",
    "DEBUG",
];

const ENV_ALLOWLIST_PREFIXES: &[&str] = &["CARGO_FEATURE_", "CARGO_CFG_"];

/// Pure safe Rust FIPS 180-4 SHA-256 implementation (zero external dependencies).
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buf_len: usize,
    total_bits: u64,
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buf_len: 0,
            total_bits: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bits = self.total_bits.wrapping_add((data.len() as u64) * 8);
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            if data.len() < need {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buffer[self.buf_len..64].copy_from_slice(&data[..need]);
            let block = self.buffer;
            self.compress(&block);
            self.buf_len = 0;
            data = &data[need..];
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.total_bits;
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            for b in &mut self.buffer[self.buf_len..64] {
                *b = 0;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buf_len = 0;
        }
        for b in &mut self.buffer[self.buf_len..56] {
            *b = 0;
        }
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    pub fn finalize_hex(self) -> String {
        let digest = self.finalize();
        let mut s = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, slot) in w.iter_mut().take(16).enumerate() {
            let off = i * 4;
            *slot =
                u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// Typed reason why `xwork-rustc` bypassed caching and executed `rustc` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "rust_shed::serde", rename_all = "kebab-case")]
pub enum PassthroughReason {
    PrintOrVersion,
    IncrementalCompilation,
    TestHarness,
    NonHermeticCrateType,
    MissingOutDir,
    MissingCrateName,
    MissingSourceFile,
}

impl PassthroughReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrintOrVersion => "print-or-version",
            Self::IncrementalCompilation => "incremental-compilation",
            Self::TestHarness => "test-harness",
            Self::NonHermeticCrateType => "non-hermetic-crate-type",
            Self::MissingOutDir => "missing-out-dir",
            Self::MissingCrateName => "missing-crate-name",
            Self::MissingSourceFile => "missing-source-file",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheableInvocation {
    pub rustc: PathBuf,
    pub raw_args: Vec<String>,
    pub crate_name: String,
    pub crate_types: Vec<String>,
    pub out_dir: PathBuf,
    pub extra_filename: String,
    pub source_file: PathBuf,
    pub extern_files: Vec<(String, PathBuf)>,
    pub normalized_flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    Cacheable(Box<CacheableInvocation>),
    Passthrough(PassthroughReason),
}

/// Classify a `RUSTC_WRAPPER` argument vector (`args[0]` = `rustc` path, `args[1..]` = flags).
pub fn classify_rustc_argv(args: &[String]) -> Classification {
    let Some(rustc_str) = args.first() else {
        return Classification::Passthrough(PassthroughReason::PrintOrVersion);
    };
    let rustc = PathBuf::from(rustc_str);
    let rest = &args[1..];

    let mut crate_name: Option<String> = None;
    let mut crate_types: Vec<String> = Vec::new();
    let mut out_dir: Option<PathBuf> = None;
    let mut extra_filename = String::new();
    let mut source_file: Option<PathBuf> = None;
    let mut extern_files: Vec<(String, PathBuf)> = Vec::new();
    let mut normalized_flags: Vec<String> = Vec::new();

    let mut i = 0;
    while i < rest.len() {
        let arg = &rest[i];
        if arg == "-vV" || arg == "--version" || arg == "-V" || arg.starts_with("--print") {
            return Classification::Passthrough(PassthroughReason::PrintOrVersion);
        }
        if arg == "--test" {
            return Classification::Passthrough(PassthroughReason::TestHarness);
        }
        if arg == "--crate-name" {
            if let Some(val) = rest.get(i + 1) {
                if val == "build_script_build" || val == "___" {
                    return Classification::Passthrough(PassthroughReason::NonHermeticCrateType);
                }
                crate_name = Some(val.clone());
                normalized_flags.push(format!("--crate-name={val}"));
                i += 2;
                continue;
            }
        } else if let Some(val) = arg.strip_prefix("--crate-name=") {
            if val == "build_script_build" || val == "___" {
                return Classification::Passthrough(PassthroughReason::NonHermeticCrateType);
            }
            crate_name = Some(val.to_owned());
            normalized_flags.push(arg.clone());
            i += 1;
            continue;
        }

        if arg == "--crate-type" {
            if let Some(val) = rest.get(i + 1) {
                for t in val.split(',') {
                    crate_types.push(t.to_owned());
                }
                normalized_flags.push(format!("--crate-type={val}"));
                i += 2;
                continue;
            }
        } else if let Some(val) = arg.strip_prefix("--crate-type=") {
            for t in val.split(',') {
                crate_types.push(t.to_owned());
            }
            normalized_flags.push(arg.clone());
            i += 1;
            continue;
        }

        if arg == "--out-dir" {
            if let Some(val) = rest.get(i + 1) {
                out_dir = Some(PathBuf::from(val));
                i += 2;
                continue;
            }
        } else if let Some(val) = arg.strip_prefix("--out-dir=") {
            out_dir = Some(PathBuf::from(val));
            i += 1;
            continue;
        }

        if arg == "-C" {
            if let Some(val) = rest.get(i + 1) {
                if val.starts_with("incremental=") {
                    return Classification::Passthrough(PassthroughReason::IncrementalCompilation);
                }
                if let Some(ef) = val.strip_prefix("extra-filename=") {
                    extra_filename = ef.to_owned();
                }
                normalized_flags.push(format!("-C{val}"));
                i += 2;
                continue;
            }
        } else if let Some(val) = arg.strip_prefix("-C") {
            if val.starts_with("incremental=") {
                return Classification::Passthrough(PassthroughReason::IncrementalCompilation);
            }
            if let Some(ef) = val.strip_prefix("extra-filename=") {
                extra_filename = ef.to_owned();
            }
            normalized_flags.push(arg.clone());
            i += 1;
            continue;
        }

        if arg == "--extern" {
            if let Some(val) = rest.get(i + 1) {
                if let Some((name, path)) = val.split_once('=') {
                    extern_files.push((name.to_owned(), PathBuf::from(path)));
                    normalized_flags.push(format!("--extern={name}"));
                } else {
                    normalized_flags.push(format!("--extern={val}"));
                }
                i += 2;
                continue;
            }
        } else if let Some(val) = arg.strip_prefix("--extern=") {
            if let Some((name, path)) = val.split_once('=') {
                extern_files.push((name.to_owned(), PathBuf::from(path)));
                normalized_flags.push(format!("--extern={name}"));
            } else {
                normalized_flags.push(arg.clone());
            }
            i += 1;
            continue;
        }

        if (arg == "-L" || arg == "--sysroot" || arg == "--remap-path-prefix") && i + 1 < rest.len()
        {
            i += 2;
            continue;
        }
        if arg.starts_with("-L") {
            i += 1;
            continue;
        }

        if !arg.starts_with('-')
            && Path::new(arg)
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| ext == "rs")
        {
            source_file = Some(PathBuf::from(arg));
            i += 1;
            continue;
        }

        normalized_flags.push(arg.clone());
        i += 1;
    }

    let Some(crate_name) = crate_name else {
        return Classification::Passthrough(PassthroughReason::MissingCrateName);
    };
    if crate_types.is_empty()
        || !crate_types
            .iter()
            .all(|t| HERMETIC_CRATE_TYPES.contains(&t.as_str()))
    {
        return Classification::Passthrough(PassthroughReason::NonHermeticCrateType);
    }
    let Some(out_dir) = out_dir else {
        return Classification::Passthrough(PassthroughReason::MissingOutDir);
    };
    let out_dir_str = out_dir.to_string_lossy();
    if out_dir_str.contains("/build/") || out_dir_str.contains("\\build\\") {
        return Classification::Passthrough(PassthroughReason::NonHermeticCrateType);
    }
    let Some(source_file) = source_file else {
        return Classification::Passthrough(PassthroughReason::MissingSourceFile);
    };
    normalized_flags.push(format!("--out-dir={out_dir_str}"));

    normalized_flags.sort();
    extern_files.sort_by(|a, b| a.0.cmp(&b.0));

    Classification::Cacheable(Box::new(CacheableInvocation {
        rustc,
        raw_args: rest.to_vec(),
        crate_name,
        crate_types,
        out_dir,
        extra_filename,
        source_file,
        extern_files,
        normalized_flags,
    }))
}

pub fn l1_cas_root() -> PathBuf {
    if let Ok(override_dir) = env::var("XWORK_CAS_L1_DIR") {
        return PathBuf::from(override_dir);
    }
    let shm = Path::new("/dev/shm");
    if shm.is_dir() {
        return shm.join("xwork-cas-v1");
    }
    PathBuf::from("/tmp/xwork-cas-v1")
}

pub fn l2_cas_root() -> PathBuf {
    if let Ok(override_dir) = env::var("XWORK_CAS_L2_DIR") {
        return PathBuf::from(override_dir);
    }
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
    PathBuf::from(home).join(".cache/herdr-xwork/cas/v1")
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "rust_shed::serde")]
pub struct CasStats {
    pub l1_hits: u64,
    pub l2_hits: u64,
    pub misses: u64,
    pub puts: u64,
    pub saved_ms: u64,
    pub passthrough: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rust_shed::serde")]
pub struct CachedObjectManifest {
    pub key: String,
    pub crate_name: String,
    pub extra_filename: String,
    pub stdout: String,
    pub stderr: String,
    pub compile_ms: u64,
    pub files: Vec<String>,
}

fn stats_path() -> PathBuf {
    l1_cas_root().join("stats.json")
}

pub fn load_stats() -> CasStats {
    fs::read_to_string(stats_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_stats(stats: &CasStats) {
    let p = stats_path();
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(stats) {
        let tmp = p.with_extension(format!("tmp.{}", std::process::id()));
        if fs::write(&tmp, json).is_ok() {
            let _ = fs::rename(&tmp, &p);
        }
    }
}

pub fn record_passthrough(reason: PassthroughReason) {
    let mut stats = load_stats();
    *stats
        .passthrough
        .entry(reason.as_str().to_owned())
        .or_insert(0) += 1;
    save_stats(&stats);
}

fn file_mtime_len(path: &Path) -> Option<(u128, u64)> {
    let meta = fs::metadata(path).ok()?;
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some((mtime, meta.len()))
}

/// Fast memoized file hash using the L1 store `fstat/` directory, so large `.rlib`/`.rmeta`
/// dependencies are hashed once per `(mtime_ns, len)` instead of failing with `key-unavailable`.
pub fn hash_file_memoized(path: &Path) -> Option<[u8; 32]> {
    let (mtime_ns, len) = file_mtime_len(path)?;
    let mut path_hasher = Sha256::new();
    path_hasher.update(path.to_string_lossy().as_bytes());
    let path_id = path_hasher.finalize_hex();

    let fstat_dir = l1_cas_root().join("fstat");
    let memo_path = fstat_dir.join(format!("{path_id}.memo"));
    let expected_tag = format!("{mtime_ns}:{len}:");

    if let Ok(existing) = fs::read_to_string(&memo_path)
        && let Some(hex_digest) = existing.trim().strip_prefix(&expected_tag)
        && let Some(bytes) = decode_hex32(hex_digest)
    {
        return Some(bytes);
    }

    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let hex = encode_hex(&digest);

    let _ = fs::create_dir_all(&fstat_dir);
    let _ = fs::write(&memo_path, format!("{expected_tag}{hex}\n"));
    Some(digest)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn decode_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Compute or load the 32-byte platform digest under `"xwork-platform-v1\0"`.
pub fn platform_digest(rustc: &Path) -> Option<[u8; 32]> {
    let (mtime_ns, len) = file_mtime_len(rustc).unwrap_or((0, 0));
    let mut id_hasher = Sha256::new();
    id_hasher.update(rustc.to_string_lossy().as_bytes());
    let rustc_id = id_hasher.finalize_hex();

    let plat_dir = l1_cas_root().join("platforms");
    let memo_path = plat_dir.join(format!("{rustc_id}.plat"));
    let prefix = format!("{mtime_ns}:{len}:");

    if let Ok(existing) = fs::read_to_string(&memo_path)
        && let Some(hex) = existing.trim().strip_prefix(&prefix)
        && let Some(bytes) = decode_hex32(hex)
    {
        return Some(bytes);
    }

    let out = Command::new(rustc).arg("-vV").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_PLATFORM_V1);
    hasher.update(&mtime_ns.to_le_bytes());
    hasher.update(&len.to_le_bytes());
    hasher.update(&out.stdout);
    let digest = hasher.finalize();
    let hex = encode_hex(&digest);

    let _ = fs::create_dir_all(&plat_dir);
    let _ = fs::write(&memo_path, format!("{prefix}{hex}\n"));
    Some(digest)
}

fn collect_crate_sources(source_file: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let crate_src_dir = source_file.parent().unwrap_or_else(|| Path::new("."));
    let mut stack = vec![crate_src_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                files.push(p);
            }
        }
    }
    if let Some(crate_root) = crate_src_dir.parent() {
        let manifest = crate_root.join("Cargo.toml");
        if manifest.is_file() {
            files.push(manifest);
        }
    }
    if files.is_empty() && source_file.is_file() {
        files.push(source_file.to_path_buf());
    }
    files.sort();
    files.dedup();
    files
}

/// Compute the 64-character hex SHA-256 cache key under `"xwork-cache-key-v1\0"`.
pub fn compute_cache_key(inv: &CacheableInvocation) -> Option<String> {
    let plat = platform_digest(&inv.rustc)?;
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_CACHE_KEY_V1);
    hasher.update(&plat);
    hasher.update(inv.crate_name.as_bytes());
    hasher.update(&[0]);

    for flag in &inv.normalized_flags {
        hasher.update(flag.as_bytes());
        hasher.update(&[0]);
    }

    let mut env_pairs: Vec<(String, String)> = env::vars()
        .filter(|(k, _)| {
            ENV_ALLOWLIST_EXACT.contains(&k.as_str())
                || ENV_ALLOWLIST_PREFIXES.iter().any(|p| k.starts_with(p))
        })
        .collect();
    env_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in env_pairs {
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.as_bytes());
        hasher.update(&[0]);
    }

    for (name, path) in &inv.extern_files {
        let digest = hash_file_memoized(path)?;
        hasher.update(name.as_bytes());
        hasher.update(b"=");
        hasher.update(&digest);
    }

    let src_files = collect_crate_sources(&inv.source_file);
    let base_dir = inv
        .source_file
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."));
    for file in src_files {
        let rel = file.strip_prefix(base_dir).unwrap_or(&file);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(&[0]);
        let digest = hash_file_memoized(&file)?;
        hasher.update(&digest);
    }

    Some(hasher.finalize_hex())
}

fn object_dir(cas_root: &Path, key: &str) -> PathBuf {
    let prefix = &key[..2.min(key.len())];
    cas_root.join("objects").join(prefix).join(key)
}

fn restore_from_object_dir(obj_dir: &Path, out_dir: &Path) -> Option<CachedObjectManifest> {
    let manifest_bytes = fs::read_to_string(obj_dir.join("manifest.json")).ok()?;
    let manifest: CachedObjectManifest = serde_json::from_str(&manifest_bytes).ok()?;
    let files_dir = obj_dir.join("files");
    fs::create_dir_all(out_dir).ok()?;

    for name in &manifest.files {
        let src = files_dir.join(name);
        if !src.is_file() {
            return None;
        }
        let dst = out_dir.join(name);
        let tmp = out_dir.join(format!(".xwork.tmp.{}.{name}", std::process::id()));
        fs::copy(&src, &tmp).ok()?;
        fs::rename(&tmp, &dst).ok()?;
    }
    Some(manifest)
}

fn copy_object_dir(src_obj: &Path, dst_obj: &Path) -> bool {
    let Some(parent) = dst_obj.parent() else {
        return false;
    };
    if fs::create_dir_all(parent).is_err() {
        return false;
    }
    let tmp = parent.join(format!(".promote.tmp.{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    if fs::create_dir_all(tmp.join("files")).is_err() {
        return false;
    }
    if fs::copy(src_obj.join("manifest.json"), tmp.join("manifest.json")).is_err() {
        let _ = fs::remove_dir_all(&tmp);
        return false;
    }
    if let Ok(entries) = fs::read_dir(src_obj.join("files")) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if fs::copy(entry.path(), tmp.join("files").join(name)).is_err() {
                let _ = fs::remove_dir_all(&tmp);
                return false;
            }
        }
    }
    let _ = fs::remove_dir_all(dst_obj);
    fs::rename(&tmp, dst_obj).is_ok()
}

/// Try to restore artifacts for `key` from L1, then L2. An L2 hit is promoted to L1.
pub fn try_restore_cached(key: &str, out_dir: &Path) -> Option<CachedObjectManifest> {
    let l1_obj = object_dir(&l1_cas_root(), key);
    if let Some(manifest) = restore_from_object_dir(&l1_obj, out_dir) {
        let mut stats = load_stats();
        stats.l1_hits += 1;
        stats.saved_ms += manifest.compile_ms;
        save_stats(&stats);
        return Some(manifest);
    }
    let l2_obj = object_dir(&l2_cas_root(), key);
    if let Some(manifest) = restore_from_object_dir(&l2_obj, out_dir) {
        let _ = copy_object_dir(&l2_obj, &l1_obj);
        let mut stats = load_stats();
        stats.l2_hits += 1;
        stats.saved_ms += manifest.compile_ms;
        save_stats(&stats);
        return Some(manifest);
    }
    None
}

fn matching_output_files(inv: &CacheableInvocation) -> Vec<String> {
    let Ok(entries) = fs::read_dir(&inv.out_dir) else {
        return Vec::new();
    };
    let stem = format!("{}{}", inv.crate_name, inv.extra_filename);
    let lib_stem = format!("lib{}{}", inv.crate_name, inv.extra_filename);
    let mut matched = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !matches!(ext, "rlib" | "rmeta" | "dylib" | "so" | "d") {
            continue;
        }
        if name.starts_with(&stem) || name.starts_with(&lib_stem) {
            matched.push(name.to_owned());
        }
    }
    matched.sort();
    matched
}

fn write_object_to_tier(
    cas_root: &Path,
    key: &str,
    out_dir: &Path,
    manifest: &CachedObjectManifest,
) -> bool {
    let obj_dir = object_dir(cas_root, key);
    let Some(parent) = obj_dir.parent() else {
        return false;
    };
    if fs::create_dir_all(parent).is_err() {
        return false;
    }
    let tmp = parent.join(format!(".put.tmp.{}.{key}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    if fs::create_dir_all(tmp.join("files")).is_err() {
        return false;
    }
    for name in &manifest.files {
        if fs::copy(out_dir.join(name), tmp.join("files").join(name)).is_err() {
            let _ = fs::remove_dir_all(&tmp);
            return false;
        }
    }
    let Ok(json) = serde_json::to_string_pretty(manifest) else {
        let _ = fs::remove_dir_all(&tmp);
        return false;
    };
    if fs::write(tmp.join("manifest.json"), json).is_err() {
        let _ = fs::remove_dir_all(&tmp);
        return false;
    }
    let _ = fs::remove_dir_all(&obj_dir);
    fs::rename(&tmp, &obj_dir).is_ok()
}

pub fn store_cached_outputs(
    key: &str,
    inv: &CacheableInvocation,
    stdout: &str,
    stderr: &str,
    compile_ms: u64,
) {
    let files = matching_output_files(inv);
    if files.is_empty() {
        return;
    }
    let manifest = CachedObjectManifest {
        key: key.to_owned(),
        crate_name: inv.crate_name.clone(),
        extra_filename: inv.extra_filename.clone(),
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
        compile_ms,
        files,
    };
    let ok_l1 = write_object_to_tier(&l1_cas_root(), key, &inv.out_dir, &manifest);
    let ok_l2 = write_object_to_tier(&l2_cas_root(), key, &inv.out_dir, &manifest);
    if ok_l1 || ok_l2 {
        let mut stats = load_stats();
        stats.puts += 1;
        save_stats(&stats);
    }
}

/// Entry point for the `xwork-rustc` `RUSTC_WRAPPER` binary.
pub fn run_rustc_wrapper(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("xwork-rustc: expected <rustc> [args...]");
        return ExitCode::from(2);
    }
    if args.first().map(String::as_str) == Some("--version") {
        println!("xwork-rustc {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    match classify_rustc_argv(args) {
        Classification::Passthrough(reason) => {
            record_passthrough(reason);
            exec_passthrough(&args[0], &args[1..])
        }
        Classification::Cacheable(inv) => {
            let Some(key) = compute_cache_key(&inv) else {
                return exec_passthrough(&args[0], &args[1..]);
            };
            if let Some(manifest) = try_restore_cached(&key, &inv.out_dir) {
                if !manifest.stdout.is_empty() {
                    print!("{}", manifest.stdout);
                }
                if !manifest.stderr.is_empty() {
                    eprint!("{}", manifest.stderr);
                }
                return ExitCode::SUCCESS;
            }

            let mut stats = load_stats();
            stats.misses += 1;
            save_stats(&stats);

            let t0 = Instant::now();
            let Ok(output) = Command::new(&inv.rustc).args(&inv.raw_args).output() else {
                return ExitCode::from(1);
            };
            let compile_ms = t0.elapsed().as_millis() as u64;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stdout.is_empty() {
                print!("{stdout}");
            }
            if !stderr.is_empty() {
                eprint!("{stderr}");
            }
            if output.status.success() {
                store_cached_outputs(&key, &inv, &stdout, &stderr, compile_ms);
                ExitCode::SUCCESS
            } else {
                let code = output.status.code().unwrap_or(1).clamp(1, 255) as u8;
                ExitCode::from(code)
            }
        }
    }
}

fn exec_passthrough(rustc: &str, rest: &[String]) -> ExitCode {
    match Command::new(rustc).args(rest).status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1).clamp(1, 255) as u8),
        Err(err) => {
            eprintln!("xwork-rustc: failed to execute {rustc}: {err}");
            ExitCode::from(1)
        }
    }
}

fn count_objects_and_bytes(cas_root: &Path) -> (u64, u64) {
    let objects_dir = cas_root.join("objects");
    let mut objects = 0u64;
    let mut bytes = 0u64;
    let Ok(prefixes) = fs::read_dir(&objects_dir) else {
        return (0, 0);
    };
    for prefix in prefixes.flatten() {
        let Ok(keys) = fs::read_dir(prefix.path()) else {
            continue;
        };
        for key_entry in keys.flatten() {
            let p = key_entry.path();
            if p.join("manifest.json").is_file() {
                objects += 1;
                bytes += dir_bytes(&p);
            }
        }
    }
    (objects, bytes)
}

fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(meta) = entry.metadata() {
                total += meta.len();
            }
        }
    }
    total
}

/// `cargo xtask cache [stat|clear] [--json]`.
pub fn run_cache_cli(args: &[String]) -> ExitCode {
    let as_json = args.iter().any(|a| a == "--json");
    let sub = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map_or("stat", String::as_str);
    match sub {
        "stat" => {
            let stats = load_stats();
            let (l1, l2) = (l1_cas_root(), l2_cas_root());
            let (l1_objs, l1_bytes) = count_objects_and_bytes(&l1);
            let (l2_objs, l2_bytes) = count_objects_and_bytes(&l2);
            let hits = stats.l1_hits + stats.l2_hits;
            if as_json {
                let report = serde_json::json!({
                    "l1_root": l1, "l2_root": l2,
                    "l1_hits": stats.l1_hits, "l2_hits": stats.l2_hits,
                    "misses": stats.misses, "puts": stats.puts,
                    "saved_ms": stats.saved_ms, "passthrough": stats.passthrough,
                    "l1_objects": l1_objs, "l1_bytes": l1_bytes,
                    "l2_objects": l2_objs, "l2_bytes": l2_bytes,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            } else {
                println!("xwork cache");
                println!(
                    "  L1 {} ({l1_objs} objects, {l1_bytes} bytes)",
                    l1.display()
                );
                println!(
                    "  L2 {} ({l2_objs} objects, {l2_bytes} bytes)",
                    l2.display()
                );
                println!(
                    "  hits {hits} (L1 {} / L2 {}), misses {}, puts {}, saved {} ms",
                    stats.l1_hits, stats.l2_hits, stats.misses, stats.puts, stats.saved_ms
                );
            }
            ExitCode::SUCCESS
        }
        "clear" => {
            for root in [l1_cas_root(), l2_cas_root()] {
                let _ = fs::remove_dir_all(&root);
            }
            println!("xwork cache cleared");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!(
                "unknown cache subcommand {other:?}; usage: cargo xtask cache [stat|clear] [--json]"
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_nist_vectors() {
        let mut empty = Sha256::new();
        empty.update(b"");
        assert_eq!(
            empty.finalize_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let mut abc = Sha256::new();
        abc.update(b"abc");
        assert_eq!(
            abc.finalize_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn classifier_accepts_hermetic_lib_and_rejects_passthroughs() {
        let v_args = vec!["rustc".to_owned(), "-vV".to_owned()];
        assert_eq!(
            classify_rustc_argv(&v_args),
            Classification::Passthrough(PassthroughReason::PrintOrVersion)
        );

        let bin_args = vec![
            "rustc".to_owned(),
            "--crate-name".to_owned(),
            "vilicus".to_owned(),
            "--crate-type".to_owned(),
            "bin".to_owned(),
            "--out-dir".to_owned(),
            "/tmp/out".to_owned(),
            "src/main.rs".to_owned(),
        ];
        assert_eq!(
            classify_rustc_argv(&bin_args),
            Classification::Passthrough(PassthroughReason::NonHermeticCrateType)
        );

        let incr_args = vec![
            "rustc".to_owned(),
            "--crate-name".to_owned(),
            "jury_core".to_owned(),
            "--crate-type".to_owned(),
            "rlib".to_owned(),
            "-C".to_owned(),
            "incremental=/tmp/inc".to_owned(),
            "--out-dir".to_owned(),
            "/tmp/out".to_owned(),
            "src/lib.rs".to_owned(),
        ];
        assert_eq!(
            classify_rustc_argv(&incr_args),
            Classification::Passthrough(PassthroughReason::IncrementalCompilation)
        );

        let ok_args = vec![
            "rustc".to_owned(),
            "--crate-name".to_owned(),
            "jury_core".to_owned(),
            "--crate-type".to_owned(),
            "rlib".to_owned(),
            "-C".to_owned(),
            "extra-filename=-1234abcd".to_owned(),
            "--out-dir".to_owned(),
            "/tmp/out".to_owned(),
            "crates/jury-core/src/lib.rs".to_owned(),
        ];
        match classify_rustc_argv(&ok_args) {
            Classification::Cacheable(inv) => {
                assert_eq!(inv.crate_name, "jury_core");
                assert_eq!(inv.extra_filename, "-1234abcd");
                assert_eq!(inv.crate_types, vec!["rlib".to_owned()]);
            }
            other => panic!("expected Cacheable, got {other:?}"),
        }
    }
}
