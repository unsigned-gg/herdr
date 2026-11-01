//! Verified Wire-Protocol & Delta-Encoding Primitives (`SPEC-0013`).
//!
//! Incorporates the `cerebral-work/scorcher` (`Spec 0007`, PRs #9 and #10) and XERJ network
//! protocol corpus primitives into `rust-shed` with zero I/O dependencies:
//! 1. **RFC 9000 §16 2-Bit Prefix Varints + 64-Bit ZigZag** (`encode_quic_varint`, `decode_quic_varint`).
//! 2. **`"SCDS"` v1 Structured `DeltaStream` Wire Codec & `DeltaStreamView<'a>`** (string interning +
//!    monotonic `seq_id` deltas + Gorilla/Chimp timestamp delta-of-delta + zero-copy borrowed view).
//! 3. **`"SCDP"` v1 Content-Addressed VCDIFF Binary Delta Patch (`CasDeltaPatch` & `CasDeltaPatchView<'a>`)**
//!    using 8-byte (`u64`) common-prefix/suffix stripping and a stack-allocated `[u32; 8192]`
//!    Fibonacci hash table (`0x9E37_79B9_7F4A_7C15`).
//! 4. **XERJ Corpus Transport & Admission Primitives**:
//!    - **Homa (SIGCOMM '18) & Swift (SIGCOMM '20)** Receiver-Driven SRPT Grant Tokens (`SrptGrantToken`).
//!    - **Storj `drpcwire`** Compact Varint Frame Header (`DrpcFrameHeader`).
//!    - **Poseidon / CoDel** Ingress Sojourn-Time Shedder (`SojournShedder`).

use std::collections::HashMap;
use std::fmt;

/// Maximum integer representable by an RFC 9000 §16 62-bit variable-length integer.
pub const QUIC_VARINT_MAX: u64 = (1u64 << 62) - 1;

/// Wire magic for `"SCDS"` v1 structured `DeltaStream` frames.
pub const SCDS_MAGIC: [u8; 4] = *b"SCDS";

/// Wire magic for `"SCDP"` v1 VCDIFF content-addressed binary delta patches.
pub const SCDP_MAGIC: [u8; 4] = *b"SCDP";

/// Wire magic for `"SRPT"` v1 Homa/Swift receiver-driven grant tokens.
pub const SRPT_MAGIC: [u8; 4] = *b"SRPT";

/// 64-bit Fibonacci hashing multiplier ($\lfloor 2^{64} / \varphi \rfloor$).
const FIBONACCI_HASH_MULT: u64 = 0x9E37_79B9_7F4A_7C15;

/// Errors returned by wire-protocol and delta-encoding codecs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireDeltaError {
    /// Value exceeds RFC 9000 62-bit varint limit (`(1 << 62) - 1`).
    VarintOverflow(u64),
    /// Input buffer ended before a complete frame or varint could be read.
    UnexpectedEof,
    /// Frame magic or version byte did not match expected protocol header.
    InvalidMagic,
    /// Unsupported protocol version.
    UnsupportedVersion(u8),
    /// Interned string table entry was not valid UTF-8 or index was out of bounds.
    InvalidInternedString,
    /// Delta patch operation referenced an out-of-bounds slice in the base blob.
    InvalidPatchWindow,
    /// Reconstructed target length did not match declared `target_len`.
    TargetLengthMismatch { expected: usize, actual: usize },
}

impl fmt::Display for WireDeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarintOverflow(v) => write!(f, "varint {v} exceeds 62-bit RFC 9000 maximum"),
            Self::UnexpectedEof => write!(f, "unexpected EOF while decoding wire frame"),
            Self::InvalidMagic => write!(f, "invalid wire protocol magic bytes"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported wire protocol version {v}"),
            Self::InvalidInternedString => {
                write!(f, "invalid UTF-8 or out-of-bounds interned string")
            },
            Self::InvalidPatchWindow => write!(f, "delta patch copy window out of bounds"),
            Self::TargetLengthMismatch { expected, actual } => {
                write!(f, "delta patch target length mismatch: expected {expected}, got {actual}")
            },
        }
    }
}

impl std::error::Error for WireDeltaError {}

// ============================================================================
// 1. RFC 9000 §16 2-Bit Prefix Varints + 64-Bit ZigZag
// ============================================================================

/// Encode an unsigned 62-bit integer into `out` using RFC 9000 §16 2-bit length prefix encoding
/// (`00` = 1B, `01` = 2B, `10` = 4B, `11` = 8B, big-endian).
#[inline]
pub fn encode_quic_varint(val: u64, out: &mut Vec<u8>) -> Result<usize, WireDeltaError> {
    if val <= 63 {
        out.push(val as u8);
        Ok(1)
    } else if val <= 16_383 {
        let b = (val as u16) | 0x4000;
        out.extend_from_slice(&b.to_be_bytes());
        Ok(2)
    } else if val <= 1_073_741_823 {
        let b = (val as u32) | 0x8000_0000;
        out.extend_from_slice(&b.to_be_bytes());
        Ok(4)
    } else if val <= QUIC_VARINT_MAX {
        let b = val | 0xC000_0000_0000_0000;
        out.extend_from_slice(&b.to_be_bytes());
        Ok(8)
    } else {
        Err(WireDeltaError::VarintOverflow(val))
    }
}

/// Decode an RFC 9000 §16 variable-length integer from the start of `buf`,
/// returning `(decoded_value, bytes_consumed)`.
#[inline]
pub fn decode_quic_varint(buf: &[u8]) -> Result<(u64, usize), WireDeltaError> {
    let Some(&first) = buf.first() else {
        return Err(WireDeltaError::UnexpectedEof);
    };
    let tag = first >> 6;
    let len = 1usize << tag;
    if buf.len() < len {
        return Err(WireDeltaError::UnexpectedEof);
    }
    let val = match len {
        1 => u64::from(first & 0x3F),
        2 => {
            let raw = u16::from_be_bytes([buf[0] & 0x3F, buf[1]]);
            u64::from(raw)
        },
        4 => {
            let raw = u32::from_be_bytes([buf[0] & 0x3F, buf[1], buf[2], buf[3]]);
            u64::from(raw)
        },
        8 => u64::from_be_bytes([
            buf[0] & 0x3F,
            buf[1],
            buf[2],
            buf[3],
            buf[4],
            buf[5],
            buf[6],
            buf[7],
        ]),
        _ => return Err(WireDeltaError::UnexpectedEof),
    };
    Ok((val, len))
}

/// Map a signed 64-bit integer to an unsigned 64-bit integer via ZigZag bijection
/// (`0 -> 0`, `-1 -> 1`, `1 -> 2`, `-2 -> 3`).
#[inline]
pub const fn zigzag_encode_i64(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

/// Invert [`zigzag_encode_i64`] back to a signed 64-bit integer.
#[inline]
pub const fn zigzag_decode_u64(z: u64) -> i64 {
    ((z >> 1) as i64) ^ (-((z & 1) as i64))
}

// ============================================================================
// 2. "SCDS" v1 Structured DeltaStream Wire Codec & Zero-Copy DeltaStreamView<'a>
// ============================================================================

/// Flag bit indicating that `OpDeltaEntry::digest` carries a non-zero 32-byte binary digest.
pub const OP_DELTA_FLAG_HAS_DIGEST: u8 = 0x80;

/// Single operation entry inside a structured [`DeltaStream`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpDeltaEntry {
    pub seq_id: u64,
    pub timestamp_ms: i64,
    pub path: String,
    pub turn_id: String,
    pub op_kind: u8,
    pub flags: u8,
    pub digest: [u8; 32],
    pub payload_len: u64,
}

/// `"SCDS"` v1 structured delta stream with string interning (`path_table`, `turn_table`),
/// monotonic `seq_id` varint deltas, and Gorilla/Chimp timestamp delta-of-delta compression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaStream {
    pub run_hash: [u8; 32],
    pub entries: Vec<OpDeltaEntry>,
}

/// Borrowed zero-copy view (`buffa` pattern) over an `"SCDS"` v1 frame (`SPEC-0013`).
///
/// Validates the header and exposes interned string tables (`paths`, `turns`) as borrowed
/// `&'a str` slices directly into the wire buffer with zero heap string allocations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaStreamView<'a> {
    pub version: u8,
    pub flags: u8,
    pub run_hash: &'a [u8],
    pub paths: Vec<&'a str>,
    pub turns: Vec<&'a str>,
    pub entry_count: usize,
    pub ops_body: &'a [u8],
}

impl DeltaStream {
    /// Encode this stream into the compact `"SCDS"` v1 binary wire format.
    pub fn encode(&self) -> Result<Vec<u8>, WireDeltaError> {
        let mut out = Vec::with_capacity(128 + self.entries.len() * 24);
        out.extend_from_slice(&SCDS_MAGIC);
        out.push(1u8); // version = 1
        let has_run_hash = self.run_hash.iter().any(|&b| b != 0);
        let stream_flags = if has_run_hash { 0x01u8 } else { 0x00u8 };
        out.push(stream_flags);
        if has_run_hash {
            out.extend_from_slice(&self.run_hash);
        }

        // Build deduplicated string tables (`path_table` and `turn_table`)
        let mut path_table: Vec<&str> = Vec::new();
        let mut path_index: HashMap<&str, usize> = HashMap::new();
        let mut turn_table: Vec<&str> = Vec::new();
        let mut turn_index: HashMap<&str, usize> = HashMap::new();

        for entry in &self.entries {
            if !path_index.contains_key(entry.path.as_str()) {
                let idx = path_table.len();
                path_table.push(entry.path.as_str());
                path_index.insert(entry.path.as_str(), idx);
            }
            if !turn_index.contains_key(entry.turn_id.as_str()) {
                let idx = turn_table.len();
                turn_table.push(entry.turn_id.as_str());
                turn_index.insert(entry.turn_id.as_str(), idx);
            }
        }

        encode_quic_varint(path_table.len() as u64, &mut out)?;
        for s in &path_table {
            encode_quic_varint(s.len() as u64, &mut out)?;
            out.extend_from_slice(s.as_bytes());
        }

        encode_quic_varint(turn_table.len() as u64, &mut out)?;
        for s in &turn_table {
            encode_quic_varint(s.len() as u64, &mut out)?;
            out.extend_from_slice(s.as_bytes());
        }

        encode_quic_varint(self.entries.len() as u64, &mut out)?;

        let mut prev_seq: i64 = 0;
        let mut prev_ts: i64 = 0;
        let mut prev_ts_delta: i64 = 0;

        for entry in &self.entries {
            let seq_delta = (entry.seq_id as i64).wrapping_sub(prev_seq);
            prev_seq = entry.seq_id as i64;
            encode_quic_varint(zigzag_encode_i64(seq_delta), &mut out)?;

            // Gorilla/Chimp second-order timestamp delta-of-delta
            let ts_delta = entry.timestamp_ms.wrapping_sub(prev_ts);
            let ts_dod = ts_delta.wrapping_sub(prev_ts_delta);
            prev_ts = entry.timestamp_ms;
            prev_ts_delta = ts_delta;
            encode_quic_varint(zigzag_encode_i64(ts_dod), &mut out)?;

            let p_idx = path_index.get(entry.path.as_str()).copied().unwrap_or(0);
            let t_idx = turn_index.get(entry.turn_id.as_str()).copied().unwrap_or(0);
            encode_quic_varint(p_idx as u64, &mut out)?;
            encode_quic_varint(t_idx as u64, &mut out)?;

            let has_digest = entry.digest.iter().any(|&b| b != 0);
            let flags = if has_digest {
                entry.flags | OP_DELTA_FLAG_HAS_DIGEST
            } else {
                entry.flags & !OP_DELTA_FLAG_HAS_DIGEST
            };
            out.push(entry.op_kind);
            out.push(flags);
            if has_digest {
                out.extend_from_slice(&entry.digest);
            }
            encode_quic_varint(entry.payload_len, &mut out)?;
        }

        Ok(out)
    }

    /// Decode an `"SCDS"` v1 binary frame into a full [`DeltaStream`].
    pub fn decode(buf: &[u8]) -> Result<Self, WireDeltaError> {
        let view = DeltaStreamView::parse_zero_copy(buf)?;
        let mut run_hash = [0u8; 32];
        if view.run_hash.len() == 32 {
            run_hash.copy_from_slice(view.run_hash);
        }

        let mut cursor = view.ops_body;
        let mut entries = Vec::with_capacity(view.entry_count);
        let mut prev_seq: i64 = 0;
        let mut prev_ts: i64 = 0;
        let mut prev_ts_delta: i64 = 0;

        for _ in 0..view.entry_count {
            let (seq_z, n1) = decode_quic_varint(cursor)?;
            cursor = &cursor[n1..];
            let seq_delta = zigzag_decode_u64(seq_z);
            let seq_id = prev_seq.wrapping_add(seq_delta);
            prev_seq = seq_id;

            let (ts_dod_z, n2) = decode_quic_varint(cursor)?;
            cursor = &cursor[n2..];
            let ts_dod = zigzag_decode_u64(ts_dod_z);
            let ts_delta = prev_ts_delta.wrapping_add(ts_dod);
            let timestamp_ms = prev_ts.wrapping_add(ts_delta);
            prev_ts = timestamp_ms;
            prev_ts_delta = ts_delta;

            let (p_idx, n3) = decode_quic_varint(cursor)?;
            cursor = &cursor[n3..];
            let (t_idx, n4) = decode_quic_varint(cursor)?;
            cursor = &cursor[n4..];

            let Some(&path_str) = view.paths.get(p_idx as usize) else {
                return Err(WireDeltaError::InvalidInternedString);
            };
            let Some(&turn_str) = view.turns.get(t_idx as usize) else {
                return Err(WireDeltaError::InvalidInternedString);
            };

            if cursor.len() < 2 {
                return Err(WireDeltaError::UnexpectedEof);
            }
            let op_kind = cursor[0];
            let raw_flags = cursor[1];
            cursor = &cursor[2..];

            let mut digest = [0u8; 32];
            if (raw_flags & OP_DELTA_FLAG_HAS_DIGEST) != 0 {
                if cursor.len() < 32 {
                    return Err(WireDeltaError::UnexpectedEof);
                }
                digest.copy_from_slice(&cursor[..32]);
                cursor = &cursor[32..];
            }

            let (payload_len, n5) = decode_quic_varint(cursor)?;
            cursor = &cursor[n5..];

            entries.push(OpDeltaEntry {
                seq_id: seq_id as u64,
                timestamp_ms,
                path: path_str.to_owned(),
                turn_id: turn_str.to_owned(),
                op_kind,
                flags: raw_flags & !OP_DELTA_FLAG_HAS_DIGEST,
                digest,
                payload_len,
            });
        }

        Ok(Self { run_hash, entries })
    }
}

impl<'a> DeltaStreamView<'a> {
    /// Parse an `"SCDS"` v1 frame without allocating heap `String`s for the interned tables.
    pub fn parse_zero_copy(buf: &'a [u8]) -> Result<Self, WireDeltaError> {
        if buf.len() < 6 {
            return Err(WireDeltaError::UnexpectedEof);
        }
        if buf[0..4] != SCDS_MAGIC {
            return Err(WireDeltaError::InvalidMagic);
        }
        let version = buf[4];
        if version != 1 {
            return Err(WireDeltaError::UnsupportedVersion(version));
        }
        let flags = buf[5];
        let mut cursor = &buf[6..];

        let run_hash = if (flags & 0x01) != 0 {
            if cursor.len() < 32 {
                return Err(WireDeltaError::UnexpectedEof);
            }
            let rh = &cursor[..32];
            cursor = &cursor[32..];
            rh
        } else {
            &[][..]
        };

        let (path_count, n_pc) = decode_quic_varint(cursor)?;
        cursor = &cursor[n_pc..];
        let mut paths = Vec::with_capacity((path_count as usize).min(4096));
        for _ in 0..path_count {
            let (slen, n_s) = decode_quic_varint(cursor)?;
            cursor = &cursor[n_s..];
            let slen = slen as usize;
            if cursor.len() < slen {
                return Err(WireDeltaError::UnexpectedEof);
            }
            let Ok(s) = std::str::from_utf8(&cursor[..slen]) else {
                return Err(WireDeltaError::InvalidInternedString);
            };
            paths.push(s);
            cursor = &cursor[slen..];
        }

        let (turn_count, n_tc) = decode_quic_varint(cursor)?;
        cursor = &cursor[n_tc..];
        let mut turns = Vec::with_capacity((turn_count as usize).min(4096));
        for _ in 0..turn_count {
            let (slen, n_s) = decode_quic_varint(cursor)?;
            cursor = &cursor[n_s..];
            let slen = slen as usize;
            if cursor.len() < slen {
                return Err(WireDeltaError::UnexpectedEof);
            }
            let Ok(s) = std::str::from_utf8(&cursor[..slen]) else {
                return Err(WireDeltaError::InvalidInternedString);
            };
            turns.push(s);
            cursor = &cursor[slen..];
        }

        let (entry_count, n_ec) = decode_quic_varint(cursor)?;
        cursor = &cursor[n_ec..];

        Ok(Self {
            version,
            flags,
            run_hash,
            paths,
            turns,
            entry_count: entry_count as usize,
            ops_body: cursor,
        })
    }
}

// ============================================================================
// 3. "SCDP" v1 Content-Addressed VCDIFF Binary Delta Patch (Fibonacci Hash)
// ============================================================================

/// VCDIFF-style binary delta instruction inside a [`CasDeltaPatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaOp {
    /// Copy `len` bytes starting at `offset` from the base CAS blob (`op = 0x01`).
    Copy { offset: u32, len: u32 },
    /// Insert literal bytes directly into the target stream (`op = 0x02`).
    Insert(Vec<u8>),
    /// Repeat `byte` `len` times (`op = 0x03`).
    Run { len: u32, byte: u8 },
}

/// `"SCDP"` v1 content-addressed VCDIFF binary delta patch anchored by `base_digest`
/// and `target_digest` (`SPEC-0013`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasDeltaPatch {
    pub base_digest: [u8; 32],
    pub target_digest: [u8; 32],
    pub target_len: u32,
    pub ops: Vec<DeltaOp>,
}

/// Borrowed zero-copy header view over an `"SCDP"` v1 binary patch frame (`buffa` pattern).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasDeltaPatchView<'a> {
    pub version: u8,
    pub base_digest: &'a [u8],
    pub target_digest: &'a [u8],
    pub target_len: u32,
    pub op_count: usize,
    pub ops_body: &'a [u8],
}

#[inline]
fn fib_hash_u64(word: u64) -> usize {
    // Map 64-bit word into 0..8192 (13 bits: 64 - 13 = 51)
    (word.wrapping_mul(FIBONACCI_HASH_MULT) >> 51) as usize
}

#[inline]
fn read_u64_le(slice: &[u8], offset: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&slice[offset..offset + 8]);
    u64::from_le_bytes(b)
}

impl CasDeltaPatch {
    /// Compute a compact `"SCDP"` v1 delta patch transforming `base` into `target`
    /// using 8-byte (`u64`) common-prefix/common-suffix stripping and a stack-allocated
    /// `[u32; 8192]` Fibonacci hash table with zero heap hash-table allocations.
    pub fn compute(
        base: &[u8],
        target: &[u8],
        base_digest: [u8; 32],
        target_digest: [u8; 32],
    ) -> Self {
        let mut ops = Vec::new();
        let target_len = target.len() as u32;
        if target.is_empty() {
            return Self { base_digest, target_digest, target_len: 0, ops };
        }

        // Step 1: 8-byte (`u64`) fast common-prefix stripping
        let min_len = base.len().min(target.len());
        let mut prefix_len = 0usize;
        while prefix_len + 8 <= min_len
            && read_u64_le(base, prefix_len) == read_u64_le(target, prefix_len)
        {
            prefix_len += 8;
        }
        while prefix_len < min_len && base[prefix_len] == target[prefix_len] {
            prefix_len += 1;
        }

        if prefix_len == target.len() && prefix_len <= base.len() {
            ops.push(DeltaOp::Copy { offset: 0, len: prefix_len as u32 });
            return Self { base_digest, target_digest, target_len, ops };
        }

        // Step 2: 8-byte (`u64`) fast common-suffix stripping
        let mut suffix_len = 0usize;
        let max_suffix = (base.len() - prefix_len).min(target.len() - prefix_len);
        while suffix_len + 8 <= max_suffix
            && read_u64_le(base, base.len() - suffix_len - 8)
                == read_u64_le(target, target.len() - suffix_len - 8)
        {
            suffix_len += 8;
        }
        while suffix_len < max_suffix
            && base[base.len() - 1 - suffix_len] == target[target.len() - 1 - suffix_len]
        {
            suffix_len += 1;
        }

        if prefix_len >= 4 {
            ops.push(DeltaOp::Copy { offset: 0, len: prefix_len as u32 });
        } else {
            prefix_len = 0;
        }

        let mid_end = target.len() - suffix_len;

        // Step 3: Stack-allocated `[u32; 8192]` Fibonacci hash table over `base`
        if mid_end > prefix_len {
            if base.len() < 8 || mid_end - prefix_len < 8 {
                Self::emit_literal_or_runs(&target[prefix_len..mid_end], &mut ops);
            } else {
                let mut table = [u32::MAX; 8192];
                let base_limit = base.len() - 8;
                // Sample stride 1 for <= 64 KiB, stride 2 for larger blobs to keep compute < 25 us
                let stride = if base.len() <= 65_536 { 1 } else { 2 };
                let mut idx = 0usize;
                while idx <= base_limit {
                    let h = fib_hash_u64(read_u64_le(base, idx));
                    table[h] = idx as u32;
                    idx += stride;
                }

                let mut lit_start = prefix_len;
                let mut pos = prefix_len;
                while pos + 8 <= mid_end {
                    let word = read_u64_le(target, pos);
                    let cand = table[fib_hash_u64(word)] as usize;
                    if cand <= base_limit && read_u64_le(base, cand) == word {
                        // Backward match extension up to `lit_start`
                        let mut b_off = cand;
                        let mut t_off = pos;
                        while b_off > 0 && t_off > lit_start && base[b_off - 1] == target[t_off - 1]
                        {
                            b_off -= 1;
                            t_off -= 1;
                        }
                        if t_off > lit_start {
                            Self::emit_literal_or_runs(&target[lit_start..t_off], &mut ops);
                        }
                        // Forward match extension
                        let mut match_len = (pos + 8) - t_off;
                        while b_off + match_len + 8 <= base.len()
                            && t_off + match_len + 8 <= mid_end
                            && read_u64_le(base, b_off + match_len)
                                == read_u64_le(target, t_off + match_len)
                        {
                            match_len += 8;
                        }
                        while b_off + match_len < base.len()
                            && t_off + match_len < mid_end
                            && base[b_off + match_len] == target[t_off + match_len]
                        {
                            match_len += 1;
                        }
                        ops.push(DeltaOp::Copy { offset: b_off as u32, len: match_len as u32 });
                        pos = t_off + match_len;
                        lit_start = pos;
                    } else {
                        pos += 1;
                    }
                }
                if lit_start < mid_end {
                    Self::emit_literal_or_runs(&target[lit_start..mid_end], &mut ops);
                }
            }
        }

        if suffix_len > 0 {
            let suffix_base_off = (base.len() - suffix_len) as u32;
            ops.push(DeltaOp::Copy { offset: suffix_base_off, len: suffix_len as u32 });
        }

        Self { base_digest, target_digest, target_len, ops }
    }

    fn emit_literal_or_runs(slice: &[u8], ops: &mut Vec<DeltaOp>) {
        if slice.is_empty() {
            return;
        }
        // If slice is a single repeated byte of length >= 16, emit `DeltaOp::Run`
        if slice.len() >= 16 {
            let first = slice[0];
            if slice.iter().all(|&b| b == first) {
                ops.push(DeltaOp::Run { len: slice.len() as u32, byte: first });
                return;
            }
        }
        ops.push(DeltaOp::Insert(slice.to_vec()));
    }

    /// Apply this delta patch to `base`, reconstructing the target CAS blob.
    pub fn apply(&self, base: &[u8]) -> Result<Vec<u8>, WireDeltaError> {
        let mut out = Vec::with_capacity(self.target_len as usize);
        for op in &self.ops {
            match op {
                DeltaOp::Copy { offset, len } => {
                    let start = *offset as usize;
                    let end = start.saturating_add(*len as usize);
                    if end > base.len() {
                        return Err(WireDeltaError::InvalidPatchWindow);
                    }
                    out.extend_from_slice(&base[start..end]);
                },
                DeltaOp::Insert(bytes) => {
                    out.extend_from_slice(bytes);
                },
                DeltaOp::Run { len, byte } => {
                    out.resize(out.len() + (*len as usize), *byte);
                },
            }
        }
        if out.len() != self.target_len as usize {
            return Err(WireDeltaError::TargetLengthMismatch {
                expected: self.target_len as usize,
                actual: out.len(),
            });
        }
        Ok(out)
    }

    /// Encode this patch into the `"SCDP"` v1 binary wire format.
    pub fn encode(&self) -> Result<Vec<u8>, WireDeltaError> {
        let mut out = Vec::with_capacity(80 + self.ops.len() * 8);
        out.extend_from_slice(&SCDP_MAGIC);
        out.push(1u8); // version = 1
        out.extend_from_slice(&self.base_digest);
        out.extend_from_slice(&self.target_digest);
        encode_quic_varint(u64::from(self.target_len), &mut out)?;
        encode_quic_varint(self.ops.len() as u64, &mut out)?;

        for op in &self.ops {
            match op {
                DeltaOp::Copy { offset, len } => {
                    out.push(0x01);
                    encode_quic_varint(u64::from(*offset), &mut out)?;
                    encode_quic_varint(u64::from(*len), &mut out)?;
                },
                DeltaOp::Insert(bytes) => {
                    out.push(0x02);
                    encode_quic_varint(bytes.len() as u64, &mut out)?;
                    out.extend_from_slice(bytes);
                },
                DeltaOp::Run { len, byte } => {
                    out.push(0x03);
                    encode_quic_varint(u64::from(*len), &mut out)?;
                    out.push(*byte);
                },
            }
        }
        Ok(out)
    }

    /// Decode an `"SCDP"` v1 binary wire frame into a [`CasDeltaPatch`].
    pub fn decode(buf: &[u8]) -> Result<Self, WireDeltaError> {
        let view = CasDeltaPatchView::parse_zero_copy(buf)?;
        let mut base_digest = [0u8; 32];
        base_digest.copy_from_slice(view.base_digest);
        let mut target_digest = [0u8; 32];
        target_digest.copy_from_slice(view.target_digest);

        let mut cursor = view.ops_body;
        let mut ops = Vec::with_capacity(view.op_count);
        for _ in 0..view.op_count {
            let Some(&tag) = cursor.first() else {
                return Err(WireDeltaError::UnexpectedEof);
            };
            cursor = &cursor[1..];
            match tag {
                0x01 => {
                    let (offset, n1) = decode_quic_varint(cursor)?;
                    cursor = &cursor[n1..];
                    let (len, n2) = decode_quic_varint(cursor)?;
                    cursor = &cursor[n2..];
                    ops.push(DeltaOp::Copy { offset: offset as u32, len: len as u32 });
                },
                0x02 => {
                    let (len, n1) = decode_quic_varint(cursor)?;
                    cursor = &cursor[n1..];
                    let len = len as usize;
                    if cursor.len() < len {
                        return Err(WireDeltaError::UnexpectedEof);
                    }
                    ops.push(DeltaOp::Insert(cursor[..len].to_vec()));
                    cursor = &cursor[len..];
                },
                0x03 => {
                    let (len, n1) = decode_quic_varint(cursor)?;
                    cursor = &cursor[n1..];
                    let Some(&byte) = cursor.first() else {
                        return Err(WireDeltaError::UnexpectedEof);
                    };
                    cursor = &cursor[1..];
                    ops.push(DeltaOp::Run { len: len as u32, byte });
                },
                _ => return Err(WireDeltaError::InvalidMagic),
            }
        }

        Ok(Self {
            base_digest,
            target_digest,
            target_len: view.target_len,
            ops,
        })
    }
}

impl<'a> CasDeltaPatchView<'a> {
    /// Inspect an `"SCDP"` v1 header and digest pair in zero copy (`buffa` pattern).
    pub fn parse_zero_copy(buf: &'a [u8]) -> Result<Self, WireDeltaError> {
        if buf.len() < 69 {
            return Err(WireDeltaError::UnexpectedEof);
        }
        if buf[0..4] != SCDP_MAGIC {
            return Err(WireDeltaError::InvalidMagic);
        }
        let version = buf[4];
        if version != 1 {
            return Err(WireDeltaError::UnsupportedVersion(version));
        }
        let base_digest = &buf[5..37];
        let target_digest = &buf[37..69];
        let mut cursor = &buf[69..];
        let (target_len, n1) = decode_quic_varint(cursor)?;
        cursor = &cursor[n1..];
        let (op_count, n2) = decode_quic_varint(cursor)?;
        cursor = &cursor[n2..];

        Ok(Self {
            version,
            base_digest,
            target_digest,
            target_len: target_len as u32,
            op_count: op_count as usize,
            ops_body: cursor,
        })
    }
}

// ============================================================================
// 4. XERJ Corpus Transport, Receiver-Driven SRPT & Sojourn-Shedding Primitives
// ============================================================================

/// Homa (SIGCOMM '18) & Swift (SIGCOMM '20) receiver-driven SRPT grant token (`SPEC-0013`).
///
/// Maps remaining message bytes to one of 8 hardware/DSCP priority queues (`0 = highest SRPT`)
/// and bounds unscheduled RTT-bytes plus fabric delay target (`fabric_delay_target_us`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrptGrantToken {
    pub stream_id: u64,
    pub offset: u64,
    pub granted_bytes: u32,
    pub priority_rank: u8,
    pub unscheduled_rtt_bytes: u32,
    pub fabric_delay_target_us: u16,
}

impl SrptGrantToken {
    /// Fixed wire size of an `"SRPT"` v1 grant frame (`32` bytes).
    pub const WIRE_SIZE: usize = 32;

    /// Compute Homa SRPT priority rank (`0..=7`, where `0` is highest priority for shortest
    /// remaining flows) from remaining bytes.
    #[inline]
    pub const fn compute_srpt_priority(remaining_bytes: u64) -> u8 {
        if remaining_bytes <= 4_096 {
            0
        } else if remaining_bytes <= 16_384 {
            1
        } else if remaining_bytes <= 65_536 {
            2
        } else if remaining_bytes <= 262_144 {
            3
        } else if remaining_bytes <= 1_048_576 {
            4
        } else if remaining_bytes <= 4_194_304 {
            5
        } else if remaining_bytes <= 16_777_216 {
            6
        } else {
            7
        }
    }

    /// Encode this grant token into a fixed 32-byte `"SRPT"` v1 frame.
    #[inline]
    pub fn to_bytes(&self) -> [u8; Self::WIRE_SIZE] {
        let mut out = [0u8; Self::WIRE_SIZE];
        out[0..4].copy_from_slice(&SRPT_MAGIC);
        out[4] = 1; // version = 1
        out[5] = self.priority_rank;
        out[6..8].copy_from_slice(&self.fabric_delay_target_us.to_le_bytes());
        out[8..16].copy_from_slice(&self.stream_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.offset.to_le_bytes());
        out[24..28].copy_from_slice(&self.granted_bytes.to_le_bytes());
        out[28..32].copy_from_slice(&self.unscheduled_rtt_bytes.to_le_bytes());
        out
    }

    /// Decode a 32-byte `"SRPT"` v1 grant token frame.
    #[inline]
    pub fn from_bytes(buf: &[u8]) -> Result<Self, WireDeltaError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(WireDeltaError::UnexpectedEof);
        }
        if buf[0..4] != SRPT_MAGIC {
            return Err(WireDeltaError::InvalidMagic);
        }
        if buf[4] != 1 {
            return Err(WireDeltaError::UnsupportedVersion(buf[4]));
        }
        let priority_rank = buf[5];
        let fabric_delay_target_us = u16::from_le_bytes([buf[6], buf[7]]);
        let stream_id = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let offset = u64::from_le_bytes([
            buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
        ]);
        let granted_bytes = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let unscheduled_rtt_bytes = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        Ok(Self {
            stream_id,
            offset,
            granted_bytes,
            priority_rank,
            unscheduled_rtt_bytes,
            fabric_delay_target_us,
        })
    }
}

/// Storj `drpcwire` compact varint frame header (`(stream_id, msg_id, kind, done)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrpcFrameHeader {
    pub stream_id: u64,
    pub msg_id: u64,
    pub kind: u8,
    pub done: bool,
}

impl DrpcFrameHeader {
    /// Encode this header into a compact `<= 17` byte (`3 B` typical) varint header.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<usize, WireDeltaError> {
        let start_len = out.len();
        let control = (self.kind & 0x7F) | if self.done { 0x80 } else { 0x00 };
        out.push(control);
        encode_quic_varint(self.stream_id, out)?;
        encode_quic_varint(self.msg_id, out)?;
        Ok(out.len() - start_len)
    }

    /// Decode a `DrpcFrameHeader` from `buf`, returning `(header, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), WireDeltaError> {
        let Some(&control) = buf.first() else {
            return Err(WireDeltaError::UnexpectedEof);
        };
        let kind = control & 0x7F;
        let done = (control & 0x80) != 0;
        let (stream_id, n1) = decode_quic_varint(&buf[1..])?;
        let (msg_id, n2) = decode_quic_varint(&buf[1 + n1..])?;
        Ok((Self { stream_id, msg_id, kind, done }, 1 + n1 + n2))
    }
}

/// Verdict returned by [`SojournShedder::evaluate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SojournVerdict {
    /// Queue sojourn time is within budget or has not persisted across the CoDel interval.
    Admit { sojourn_ns: u64 },
    /// Queue sojourn time exceeded `target_sojourn_ns` continuously for `interval_ns`; shed load.
    Shed { sojourn_ns: u64, sustained_ns: u64 },
}

/// Poseidon / CoDel (Controlled Delay) ingress sojourn-time shedder (`SPEC-0013`).
#[derive(Debug, Clone)]
pub struct SojournShedder {
    pub target_sojourn_ns: u64,
    pub interval_ns: u64,
    first_above_time_ns: Option<u64>,
    pub shed_count: u64,
}

impl Default for SojournShedder {
    fn default() -> Self {
        Self::new(5_000_000, 100_000_000) // 5 ms target sojourn, 100 ms CoDel interval
    }
}

impl SojournShedder {
    pub const fn new(target_sojourn_ns: u64, interval_ns: u64) -> Self {
        Self {
            target_sojourn_ns,
            interval_ns,
            first_above_time_ns: None,
            shed_count: 0,
        }
    }

    /// Evaluate a packet/request that was enqueued at `enqueue_at_ns` and dequeued at `now_ns`.
    pub fn evaluate(&mut self, enqueue_at_ns: u64, now_ns: u64) -> SojournVerdict {
        let sojourn_ns = now_ns.saturating_sub(enqueue_at_ns);
        if sojourn_ns <= self.target_sojourn_ns {
            self.first_above_time_ns = None;
            return SojournVerdict::Admit { sojourn_ns };
        }
        match self.first_above_time_ns {
            None => {
                self.first_above_time_ns = Some(now_ns);
                SojournVerdict::Admit { sojourn_ns }
            },
            Some(first_ns) => {
                let sustained_ns = now_ns.saturating_sub(first_ns);
                if sustained_ns >= self.interval_ns {
                    self.shed_count += 1;
                    SojournVerdict::Shed { sojourn_ns, sustained_ns }
                } else {
                    SojournVerdict::Admit { sojourn_ns }
                }
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rfc9000_varint_and_zigzag_roundtrip_all_tiers() {
        let samples = [
            0u64,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            QUIC_VARINT_MAX,
        ];
        for &v in &samples {
            let mut buf = Vec::new();
            let written = encode_quic_varint(v, &mut buf).unwrap();
            let (decoded, consumed) = decode_quic_varint(&buf).unwrap();
            assert_eq!(written, consumed);
            assert_eq!(v, decoded);
        }
        assert_eq!(
            encode_quic_varint(QUIC_VARINT_MAX + 1, &mut Vec::new()),
            Err(WireDeltaError::VarintOverflow(QUIC_VARINT_MAX + 1))
        );

        for s in [
            -1_000_000i64,
            -2,
            -1,
            0,
            1,
            2,
            1_000_000,
            i64::MAX,
            i64::MIN,
        ] {
            assert_eq!(zigzag_decode_u64(zigzag_encode_i64(s)), s);
        }
    }

    #[test]
    fn scds_delta_stream_and_zero_copy_view_roundtrip_and_compress() {
        let mut entries = Vec::with_capacity(200);
        for i in 0..200u64 {
            entries.push(OpDeltaEntry {
                seq_id: 1000 + i,
                timestamp_ms: 1_761_440_000_000i64 + (i as i64) * 25,
                path: format!("crates/scorcher-core/src/module_{}.rs", i % 6),
                turn_id: format!("turn-estate-w4z-{}", i % 4),
                op_kind: (i % 3) as u8,
                flags: 0x01,
                digest: if i % 5 == 0 { [0xAB; 32] } else { [0u8; 32] },
                payload_len: 4096 + (i * 128),
            });
        }
        let stream = DeltaStream { run_hash: [0x42; 32], entries };
        let wire = stream.encode().unwrap();

        // Zero-copy view (`buffa` pattern) borrows interned paths & turns directly from `wire`
        let view = DeltaStreamView::parse_zero_copy(&wire).unwrap();
        assert_eq!(view.paths.len(), 6);
        assert_eq!(view.turns.len(), 4);
        assert_eq!(view.entry_count, 200);
        assert!(wire.len() < 4_500, "expected SCDS wire size < 4.5 KiB, got {} B", wire.len());

        let decoded = DeltaStream::decode(&wire).unwrap();
        assert_eq!(decoded, stream);
    }

    #[test]
    fn scdp_cas_delta_patch_fibonacci_vcdiff_compresses_64kib_over_100x() {
        let mut base = vec![0u8; 65_536];
        for (i, b) in base.iter_mut().enumerate() {
            *b = ((i.wrapping_mul(31) ^ (i >> 3)) & 0xFF) as u8;
        }
        let mut target = base.clone();
        // Modify a 128-byte window in the middle of the 64 KiB blob
        for b in &mut target[32_000..32_128] {
            *b ^= 0x5A;
        }

        let patch = CasDeltaPatch::compute(&base, &target, [0x11; 32], [0x22; 32]);
        let wire = patch.encode().unwrap();
        assert!(
            wire.len() < 450,
            "expected 64 KiB patch wire size < 450 B (>145x compression), got {} B",
            wire.len()
        );

        let view = CasDeltaPatchView::parse_zero_copy(&wire).unwrap();
        assert_eq!(view.target_len, 65_536);

        let decoded_patch = CasDeltaPatch::decode(&wire).unwrap();
        let rebuilt = decoded_patch.apply(&base).unwrap();
        assert_eq!(rebuilt, target);
    }

    #[test]
    fn srpt_grant_token_drpc_frame_and_codel_sojourn_shedder_behave_deterministically() {
        let prio_small = SrptGrantToken::compute_srpt_priority(2_048);
        let prio_large = SrptGrantToken::compute_srpt_priority(32 * 1_048_576);
        assert_eq!(prio_small, 0);
        assert_eq!(prio_large, 7);

        let token = SrptGrantToken {
            stream_id: 42,
            offset: 65_536,
            granted_bytes: 131_072,
            priority_rank: prio_small,
            unscheduled_rtt_bytes: 65_536,
            fabric_delay_target_us: 25,
        };
        let bytes = token.to_bytes();
        let decoded = SrptGrantToken::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, token);

        let hdr = DrpcFrameHeader { stream_id: 7, msg_id: 99, kind: 0x02, done: true };
        let mut hbuf = Vec::new();
        let n = hdr.encode(&mut hbuf).unwrap();
        assert!(n <= 9);
        let (dhdr, consumed) = DrpcFrameHeader::decode(&hbuf).unwrap();
        assert_eq!(dhdr, hdr);
        assert_eq!(n, consumed);

        let mut shedder = SojournShedder::new(5_000_000, 100_000_000);
        assert!(matches!(
            shedder.evaluate(0, 2_000_000),
            SojournVerdict::Admit { sojourn_ns: 2_000_000 }
        ));
        // First spike above 5ms enters tracking window, still admits
        assert!(matches!(shedder.evaluate(10_000_000, 20_000_000), SojournVerdict::Admit { .. }));
        // Sustained >5ms sojourn after 100ms interval -> Shed!
        assert!(matches!(
            shedder.evaluate(110_000_000, 125_000_000),
            SojournVerdict::Shed { .. }
        ));
        assert_eq!(shedder.shed_count, 1);
    }
}
