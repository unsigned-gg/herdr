// Derived from cerebral-work/scorcher, crates/scorcher-core/src/cas.rs and custody.rs
// (Spec 0007, REQ-0007-05..08). Licensor: 2die4 Inc. / Christian Todie (BUSL-1.1, Change License 0BSD).
// First-party code for rust-shed.

//! Binary CAS delta patch ("SCDP" v1) and structured delta stream ("SCDS" v1)
//! wire codecs with zero-copy borrowed slice views.
//!
//! Provides compact differential encoding for content-addressed storage (CAS)
//! and agent execution custody traces with zero heap allocations during view decoding.

use std::fmt;

use crate::varint::{
    VarintError, decode_len_prefixed, decode_signed_varint, decode_varint, encode_len_prefixed,
    encode_signed_varint, encode_varint,
};

/// Magic header prefix identifying a binary CAS delta patch (`"SCDP"`).
pub const CAS_DELTA_MAGIC: [u8; 4] = *b"SCDP";

/// Current wire version of [`CasDeltaPatch`].
pub const CAS_DELTA_VERSION: u8 = 1;

/// Magic header prefix identifying a structured delta stream (`"SCDS"`).
pub const DELTA_STREAM_MAGIC: [u8; 4] = *b"SCDS";

/// Current wire version of [`DeltaStreamView`].
pub const DELTA_STREAM_VERSION: u8 = 1;

/// Maximum target payload byte length reconstructible by [`CasDeltaPatch`] (64 MiB).
pub const MAX_DELTA_TARGET_BYTES: usize = 64 * 1024 * 1024;

/// Length in ASCII hex characters of a BLAKE3 digest.
pub const BLAKE3_HEX_LEN: usize = 64;

/// Minimum match/run length (in bytes) emitted as a Copy or Run instruction.
pub const MIN_DELTA_MATCH_LEN: usize = 8;

const DELTA_ANCHOR_BITS: u32 = 13;
const DELTA_ANCHOR_SLOTS: usize = 1 << DELTA_ANCHOR_BITS;

/// Error type for delta encoding and decoding operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    /// Underlying varint operation failed.
    Varint(VarintError),
    /// Invalid magic bytes on wire.
    MagicMismatch([u8; 4]),
    /// Wire format version is not supported.
    UnsupportedVersion(u8),
    /// Input frame is truncated or ended unexpectedly.
    Truncated { needed: usize, have: usize },
    /// Frame contains trailing unparsed bytes.
    TrailingBytes(usize),
    /// Target size exceeds maximum allowed size.
    TargetSizeExceeded { size: u64, max: u64 },
    /// Reconstructed size does not match declared target size.
    SizeMismatch { reconstructed: usize, expected: u64 },
    /// Base copy offset or length out of range.
    BaseOutOfRange {
        offset: u64,
        len: u64,
        base_len: usize,
    },
    /// Invalid instruction tag byte.
    InvalidInstructionTag(u8),
    /// Instruction has zero length where non-zero is required.
    ZeroLengthInstruction,
    /// Digest or string field is not valid ASCII or UTF-8.
    InvalidEncoding(&'static str),
    /// Declared element count exceeds remaining wire bytes.
    CountExceedsFrame { count: usize, remaining: usize },
    /// Sequence numbers are non-monotonic.
    NonMonotonicSeq { seq: u64, prev: u64 },
    /// Timestamp overflowed during delta computation.
    TimestampOverflow(&'static str),
    /// Invalid enum discriminant or wire flag.
    InvalidDiscriminant(&'static str, u8),
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Varint(err) => write!(f, "varint error: {err}"),
            Self::MagicMismatch(m) => write!(f, "invalid wire magic: {m:?}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported wire version: {v}"),
            Self::Truncated { needed, have } => {
                write!(f, "frame truncated: needed {needed} bytes, have {have}")
            }
            Self::TrailingBytes(n) => write!(f, "frame contains {n} unparsed trailing bytes"),
            Self::TargetSizeExceeded { size, max } => {
                write!(f, "target size {size} exceeds maximum {max}")
            }
            Self::SizeMismatch {
                reconstructed,
                expected,
            } => {
                write!(
                    f,
                    "reconstructed size {reconstructed} does not match expected {expected}"
                )
            }
            Self::BaseOutOfRange {
                offset,
                len,
                base_len,
            } => {
                write!(
                    f,
                    "copy range {offset}..{} exceeds base length {base_len}",
                    offset + len
                )
            }
            Self::InvalidInstructionTag(tag) => write!(f, "invalid delta instruction tag: {tag}"),
            Self::ZeroLengthInstruction => write!(f, "instruction has invalid zero length"),
            Self::InvalidEncoding(field) => write!(f, "invalid encoding in field: {field}"),
            Self::CountExceedsFrame { count, remaining } => {
                write!(
                    f,
                    "declared count {count} exceeds remaining bytes {remaining}"
                )
            }
            Self::NonMonotonicSeq { seq, prev } => {
                write!(f, "non-monotonic sequence {seq} after {prev}")
            }
            Self::TimestampOverflow(msg) => write!(f, "timestamp overflow: {msg}"),
            Self::InvalidDiscriminant(name, val) => {
                write!(f, "invalid discriminant for {name}: {val}")
            }
        }
    }
}

impl std::error::Error for DeltaError {}

impl From<VarintError> for DeltaError {
    fn from(err: VarintError) -> Self {
        Self::Varint(err)
    }
}

/// Owned RFC 3284 (VCDIFF)-style instruction for reconstructing a target blob from a base blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaInstruction {
    /// Copy `len` contiguous bytes starting at `offset` in the base blob.
    Copy { offset: u64, len: u64 },
    /// Insert literal bytes directly into the target buffer.
    Insert(Vec<u8>),
    /// Append `len` repetitions of `byte` into the target buffer.
    Run { len: u64, byte: u8 },
}

/// Zero-copy borrowed RFC 3284 (VCDIFF)-style instruction referencing the wire buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaInstructionView<'a> {
    /// Copy `len` contiguous bytes starting at `offset` in the base blob.
    Copy { offset: u64, len: u64 },
    /// Insert literal slice directly from the borrowed wire frame without allocation.
    Insert(&'a [u8]),
    /// Append `len` repetitions of `byte` into the target buffer.
    Run { len: u64, byte: u8 },
}

/// Content-addressed binary delta patch transforming `base_digest` into `target_digest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasDeltaPatch {
    /// BLAKE3 hex digest of the base blob.
    pub base_digest: String,
    /// BLAKE3 hex digest of the reconstructed target blob.
    pub target_digest: String,
    /// Exact byte length of the reconstructed target blob.
    pub target_size: u64,
    /// Sequence of delta instructions.
    pub instructions: Vec<DeltaInstruction>,
}

#[inline]
fn hash8_anchor(window: [u8; MIN_DELTA_MATCH_LEN]) -> usize {
    let v = u64::from_le_bytes(window);
    ((v.wrapping_mul(0x9E37_79B9_7F4A_7C15)) >> (64 - DELTA_ANCHOR_BITS)) as usize
}

#[inline]
fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    let max_len = a.len().min(b.len());
    let mut i = 0usize;
    while i + 8 <= max_len {
        let v1 = u64::from_ne_bytes(a[i..i + 8].try_into().unwrap());
        let v2 = u64::from_ne_bytes(b[i..i + 8].try_into().unwrap());
        if v1 != v2 {
            let diff = v1 ^ v2;
            let zeros = if cfg!(target_endian = "little") {
                diff.trailing_zeros() / 8
            } else {
                diff.leading_zeros() / 8
            };
            return i + zeros as usize;
        }
        i += 8;
    }
    while i < max_len && a[i] == b[i] {
        i += 1;
    }
    i
}

#[inline]
fn common_suffix_len(a: &[u8], b: &[u8], max_len: usize) -> usize {
    let mut i = 0usize;
    while i < max_len && a[a.len() - 1 - i] == b[b.len() - 1 - i] {
        i += 1;
    }
    i
}

impl CasDeltaPatch {
    /// Compute a compact delta patch transforming `base` into `target`.
    pub fn compute(base: &[u8], target: &[u8], base_digest: &str, target_digest: &str) -> Self {
        let mut instructions = Vec::new();
        if base.is_empty() {
            if !target.is_empty() {
                instructions.push(DeltaInstruction::Insert(target.to_vec()));
            }
            return Self {
                base_digest: base_digest.to_owned(),
                target_digest: target_digest.to_owned(),
                target_size: target.len() as u64,
                instructions,
            };
        }

        let prefix_len = common_prefix_len(base, target);
        if prefix_len >= MIN_DELTA_MATCH_LEN {
            instructions.push(DeltaInstruction::Copy {
                offset: 0,
                len: prefix_len as u64,
            });
        }

        let max_suffix = (base.len() - prefix_len).min(target.len() - prefix_len);
        let suffix_len = common_suffix_len(base, target, max_suffix);
        let target_end = target.len() - suffix_len;

        let mut anchors = [u32::MAX; DELTA_ANCHOR_SLOTS];
        if base.len() >= MIN_DELTA_MATCH_LEN && target_end > prefix_len {
            let max_windows = base.len() - MIN_DELTA_MATCH_LEN + 1;
            let unconsumed_base = base.len().saturating_sub(prefix_len + suffix_len);
            let unconsumed_target = target_end.saturating_sub(prefix_len);
            if unconsumed_base >= 512 || unconsumed_target >= 512 {
                let stride = (max_windows / (DELTA_ANCHOR_SLOTS / 2)).max(8);
                let mut idx = 0usize;
                while idx < max_windows {
                    let mut key = [0u8; MIN_DELTA_MATCH_LEN];
                    key.copy_from_slice(&base[idx..idx + MIN_DELTA_MATCH_LEN]);
                    let slot = hash8_anchor(key);
                    if anchors[slot] == u32::MAX {
                        anchors[slot] = idx as u32;
                    }
                    idx += stride;
                }
            }
            let mid_start = prefix_len.saturating_sub(64).min(max_windows);
            let mid_end = base
                .len()
                .saturating_sub(suffix_len)
                .saturating_add(64)
                .min(max_windows)
                .min(mid_start.saturating_add(1024));
            let mut m_idx = mid_start;
            while m_idx < mid_end {
                let mut key = [0u8; MIN_DELTA_MATCH_LEN];
                key.copy_from_slice(&base[m_idx..m_idx + MIN_DELTA_MATCH_LEN]);
                anchors[hash8_anchor(key)] = m_idx as u32;
                m_idx += 1;
            }
        }

        let mut pending_insert: Vec<u8> = Vec::new();
        let mut pos = prefix_len;

        while pos < target_end {
            let run_byte = target[pos];
            let mut run_len = 1usize;
            while pos + run_len < target_end && target[pos + run_len] == run_byte {
                run_len += 1;
            }

            let mut best_copy: Option<(usize, usize)> = None;
            if pos + MIN_DELTA_MATCH_LEN <= target_end && base.len() >= MIN_DELTA_MATCH_LEN {
                let mut window = [0u8; MIN_DELTA_MATCH_LEN];
                window.copy_from_slice(&target[pos..pos + MIN_DELTA_MATCH_LEN]);

                let mut candidate_offsets = [None, None];
                if pos + MIN_DELTA_MATCH_LEN <= base.len()
                    && base[pos..pos + MIN_DELTA_MATCH_LEN] == window
                {
                    candidate_offsets[0] = Some(pos);
                }
                let slot_val = anchors[hash8_anchor(window)];
                if slot_val != u32::MAX {
                    let anchored = slot_val as usize;
                    if anchored + MIN_DELTA_MATCH_LEN <= base.len()
                        && base[anchored..anchored + MIN_DELTA_MATCH_LEN] == window
                        && candidate_offsets[0] != Some(anchored)
                    {
                        candidate_offsets[1] = Some(anchored);
                    }
                }

                for cand in candidate_offsets.into_iter().flatten() {
                    let mlen = MIN_DELTA_MATCH_LEN
                        + common_prefix_len(
                            &base[cand + MIN_DELTA_MATCH_LEN..],
                            &target[pos + MIN_DELTA_MATCH_LEN..target_end],
                        );
                    if best_copy.is_none_or(|(_, best_len)| mlen > best_len) {
                        best_copy = Some((cand, mlen));
                    }
                }
            }

            let copy_len = best_copy.map_or(0, |(_, l)| l);
            if copy_len >= MIN_DELTA_MATCH_LEN && copy_len >= run_len {
                if let Some((mut offset, mut len)) = best_copy {
                    while offset > 0
                        && !pending_insert.is_empty()
                        && base[offset - 1] == pending_insert[pending_insert.len() - 1]
                    {
                        offset -= 1;
                        len += 1;
                        pending_insert.pop();
                    }
                    if !pending_insert.is_empty() {
                        instructions.push(DeltaInstruction::Insert(std::mem::take(
                            &mut pending_insert,
                        )));
                    }
                    instructions.push(DeltaInstruction::Copy {
                        offset: offset as u64,
                        len: len as u64,
                    });
                    pos += copy_len;
                }
            } else if run_len >= MIN_DELTA_MATCH_LEN {
                if !pending_insert.is_empty() {
                    instructions.push(DeltaInstruction::Insert(std::mem::take(
                        &mut pending_insert,
                    )));
                }
                instructions.push(DeltaInstruction::Run {
                    len: run_len as u64,
                    byte: run_byte,
                });
                pos += run_len;
            } else {
                pending_insert.push(target[pos]);
                pos += 1;
            }
        }

        if !pending_insert.is_empty() {
            instructions.push(DeltaInstruction::Insert(pending_insert));
        }

        if suffix_len >= MIN_DELTA_MATCH_LEN {
            instructions.push(DeltaInstruction::Copy {
                offset: (base.len() - suffix_len) as u64,
                len: suffix_len as u64,
            });
        } else if suffix_len > 0 {
            instructions.push(DeltaInstruction::Insert(
                target[target.len() - suffix_len..].to_vec(),
            ));
        }

        Self {
            base_digest: base_digest.to_owned(),
            target_digest: target_digest.to_owned(),
            target_size: target.len() as u64,
            instructions,
        }
    }

    /// Encode this patch into the compact `"SCDP"` binary wire format.
    pub fn encode_wire(&self) -> Result<Vec<u8>, DeltaError> {
        let mut buf = Vec::with_capacity(144 + self.instructions.len() * 8);
        buf.extend_from_slice(&CAS_DELTA_MAGIC);
        buf.push(CAS_DELTA_VERSION);
        if self.base_digest.len() != BLAKE3_HEX_LEN || self.target_digest.len() != BLAKE3_HEX_LEN {
            return Err(DeltaError::InvalidEncoding(
                "digests must be 64-char ASCII hex",
            ));
        }
        buf.extend_from_slice(self.base_digest.as_bytes());
        buf.extend_from_slice(self.target_digest.as_bytes());
        encode_varint(self.target_size, &mut buf)?;
        encode_varint(self.instructions.len() as u64, &mut buf)?;

        for inst in &self.instructions {
            match inst {
                DeltaInstruction::Copy { offset, len } => {
                    buf.push(0);
                    encode_varint(*offset, &mut buf)?;
                    encode_varint(*len, &mut buf)?;
                }
                DeltaInstruction::Insert(lit) => {
                    buf.push(1);
                    encode_len_prefixed(lit, &mut buf)?;
                }
                DeltaInstruction::Run { len, byte } => {
                    buf.push(2);
                    encode_varint(*len, &mut buf)?;
                    buf.push(*byte);
                }
            }
        }
        Ok(buf)
    }

    /// Decode an owned patch from `"SCDP"` wire bytes.
    pub fn decode_wire(bytes: &[u8]) -> Result<Self, DeltaError> {
        let view = CasDeltaPatchView::parse(bytes)?;
        let mut instructions = Vec::with_capacity(view.instruction_count);
        for inst in view.iter_instructions() {
            match inst? {
                DeltaInstructionView::Copy { offset, len } => {
                    instructions.push(DeltaInstruction::Copy { offset, len });
                }
                DeltaInstructionView::Insert(slice) => {
                    instructions.push(DeltaInstruction::Insert(slice.to_vec()));
                }
                DeltaInstructionView::Run { len, byte } => {
                    instructions.push(DeltaInstruction::Run { len, byte });
                }
            }
        }
        Ok(Self {
            base_digest: view.base_digest.to_owned(),
            target_digest: view.target_digest.to_owned(),
            target_size: view.target_size,
            instructions,
        })
    }

    /// Apply this delta patch against `base` to reconstruct the target payload.
    pub fn apply(&self, base: &[u8]) -> Result<Vec<u8>, DeltaError> {
        let target_len =
            usize::try_from(self.target_size).map_err(|_| DeltaError::TargetSizeExceeded {
                size: self.target_size,
                max: usize::MAX as u64,
            })?;
        if target_len > MAX_DELTA_TARGET_BYTES {
            return Err(DeltaError::TargetSizeExceeded {
                size: self.target_size,
                max: MAX_DELTA_TARGET_BYTES as u64,
            });
        }

        let mut out = Vec::with_capacity(target_len);
        for inst in &self.instructions {
            match inst {
                DeltaInstruction::Copy { offset, len } => {
                    let off = usize::try_from(*offset).map_err(|_| DeltaError::BaseOutOfRange {
                        offset: *offset,
                        len: *len,
                        base_len: base.len(),
                    })?;
                    let copy_len =
                        usize::try_from(*len).map_err(|_| DeltaError::BaseOutOfRange {
                            offset: *offset,
                            len: *len,
                            base_len: base.len(),
                        })?;
                    let end = off
                        .checked_add(copy_len)
                        .ok_or(DeltaError::BaseOutOfRange {
                            offset: *offset,
                            len: *len,
                            base_len: base.len(),
                        })?;
                    if end > base.len() {
                        return Err(DeltaError::BaseOutOfRange {
                            offset: *offset,
                            len: *len,
                            base_len: base.len(),
                        });
                    }
                    if out.len().saturating_add(copy_len) > target_len {
                        return Err(DeltaError::SizeMismatch {
                            reconstructed: out.len() + copy_len,
                            expected: self.target_size,
                        });
                    }
                    out.extend_from_slice(&base[off..end]);
                }
                DeltaInstruction::Insert(lit) => {
                    if lit.is_empty() {
                        return Err(DeltaError::ZeroLengthInstruction);
                    }
                    if out.len().saturating_add(lit.len()) > target_len {
                        return Err(DeltaError::SizeMismatch {
                            reconstructed: out.len() + lit.len(),
                            expected: self.target_size,
                        });
                    }
                    out.extend_from_slice(lit);
                }
                DeltaInstruction::Run { len, byte } => {
                    if *len == 0 {
                        return Err(DeltaError::ZeroLengthInstruction);
                    }
                    let run_len = usize::try_from(*len).map_err(|_| DeltaError::SizeMismatch {
                        reconstructed: usize::MAX,
                        expected: self.target_size,
                    })?;
                    if out.len().saturating_add(run_len) > target_len {
                        return Err(DeltaError::SizeMismatch {
                            reconstructed: out.len() + run_len,
                            expected: self.target_size,
                        });
                    }
                    out.resize(out.len() + run_len, *byte);
                }
            }
        }

        if out.len() != target_len {
            return Err(DeltaError::SizeMismatch {
                reconstructed: out.len(),
                expected: self.target_size,
            });
        }
        Ok(out)
    }
}

/// Zero-copy borrowed view over an `"SCDP"` binary wire frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CasDeltaPatchView<'a> {
    /// Borrowed BLAKE3 hex digest of the base blob.
    pub base_digest: &'a str,
    /// Borrowed BLAKE3 hex digest of the target blob.
    pub target_digest: &'a str,
    /// Declared byte length of the reconstructed target.
    pub target_size: u64,
    /// Declared count of delta instructions.
    pub instruction_count: usize,
    raw_instructions: &'a [u8],
}

impl<'a> CasDeltaPatchView<'a> {
    /// Parse and validate the header of an `"SCDP"` binary frame without copying payloads.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DeltaError> {
        const MIN_HEADER: usize = 4 + 1 + BLAKE3_HEX_LEN + BLAKE3_HEX_LEN;
        if bytes.len() < MIN_HEADER {
            return Err(DeltaError::Truncated {
                needed: MIN_HEADER,
                have: bytes.len(),
            });
        }
        if bytes[0..4] != CAS_DELTA_MAGIC {
            return Err(DeltaError::MagicMismatch([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ]));
        }
        let version = bytes[4];
        if version != CAS_DELTA_VERSION {
            return Err(DeltaError::UnsupportedVersion(version));
        }

        let base_digest = std::str::from_utf8(&bytes[5..5 + BLAKE3_HEX_LEN])
            .map_err(|_| DeltaError::InvalidEncoding("base_digest"))?;
        let target_digest = std::str::from_utf8(&bytes[5 + BLAKE3_HEX_LEN..5 + 2 * BLAKE3_HEX_LEN])
            .map_err(|_| DeltaError::InvalidEncoding("target_digest"))?;

        let mut cursor = MIN_HEADER;
        let (target_size, used) = decode_varint(&bytes[cursor..])?;
        cursor += used;
        if target_size > MAX_DELTA_TARGET_BYTES as u64 {
            return Err(DeltaError::TargetSizeExceeded {
                size: target_size,
                max: MAX_DELTA_TARGET_BYTES as u64,
            });
        }

        let (count_u64, used) = decode_varint(&bytes[cursor..])?;
        cursor += used;
        let instruction_count =
            usize::try_from(count_u64).map_err(|_| DeltaError::CountExceedsFrame {
                count: usize::MAX,
                remaining: 0,
            })?;
        if instruction_count > bytes.len().saturating_sub(cursor) {
            return Err(DeltaError::CountExceedsFrame {
                count: instruction_count,
                remaining: bytes.len().saturating_sub(cursor),
            });
        }

        Ok(Self {
            base_digest,
            target_digest,
            target_size,
            instruction_count,
            raw_instructions: &bytes[cursor..],
        })
    }

    /// Iterate over borrowed delta instructions with zero allocations.
    pub fn iter_instructions(&self) -> DeltaInstructionIter<'a> {
        DeltaInstructionIter {
            remaining: self.raw_instructions,
            count_remaining: self.instruction_count,
        }
    }

    /// Apply this delta view directly to reconstruct target bytes without materializing instructions.
    pub fn apply(&self, base: &[u8]) -> Result<Vec<u8>, DeltaError> {
        let target_len =
            usize::try_from(self.target_size).map_err(|_| DeltaError::TargetSizeExceeded {
                size: self.target_size,
                max: usize::MAX as u64,
            })?;
        if target_len > MAX_DELTA_TARGET_BYTES {
            return Err(DeltaError::TargetSizeExceeded {
                size: self.target_size,
                max: MAX_DELTA_TARGET_BYTES as u64,
            });
        }

        let mut out = Vec::with_capacity(target_len);
        let iter = self.iter_instructions();
        for inst in iter {
            match inst? {
                DeltaInstructionView::Copy { offset, len } => {
                    let off = usize::try_from(offset).map_err(|_| DeltaError::BaseOutOfRange {
                        offset,
                        len,
                        base_len: base.len(),
                    })?;
                    let copy_len =
                        usize::try_from(len).map_err(|_| DeltaError::BaseOutOfRange {
                            offset,
                            len,
                            base_len: base.len(),
                        })?;
                    let end = off
                        .checked_add(copy_len)
                        .ok_or(DeltaError::BaseOutOfRange {
                            offset,
                            len,
                            base_len: base.len(),
                        })?;
                    if end > base.len() {
                        return Err(DeltaError::BaseOutOfRange {
                            offset,
                            len,
                            base_len: base.len(),
                        });
                    }
                    if out.len().saturating_add(copy_len) > target_len {
                        return Err(DeltaError::SizeMismatch {
                            reconstructed: out.len() + copy_len,
                            expected: self.target_size,
                        });
                    }
                    out.extend_from_slice(&base[off..end]);
                }
                DeltaInstructionView::Insert(lit) => {
                    if lit.is_empty() {
                        return Err(DeltaError::ZeroLengthInstruction);
                    }
                    if out.len().saturating_add(lit.len()) > target_len {
                        return Err(DeltaError::SizeMismatch {
                            reconstructed: out.len() + lit.len(),
                            expected: self.target_size,
                        });
                    }
                    out.extend_from_slice(lit);
                }
                DeltaInstructionView::Run { len, byte } => {
                    if len == 0 {
                        return Err(DeltaError::ZeroLengthInstruction);
                    }
                    let run_len = usize::try_from(len).map_err(|_| DeltaError::SizeMismatch {
                        reconstructed: usize::MAX,
                        expected: self.target_size,
                    })?;
                    if out.len().saturating_add(run_len) > target_len {
                        return Err(DeltaError::SizeMismatch {
                            reconstructed: out.len() + run_len,
                            expected: self.target_size,
                        });
                    }
                    out.resize(out.len() + run_len, byte);
                }
            }
        }

        if out.len() != target_len {
            return Err(DeltaError::SizeMismatch {
                reconstructed: out.len(),
                expected: self.target_size,
            });
        }
        Ok(out)
    }
}

/// Zero-copy iterator yielding borrowed instructions from an `"SCDP"` frame.
pub struct DeltaInstructionIter<'a> {
    remaining: &'a [u8],
    count_remaining: usize,
}

impl<'a> Iterator for DeltaInstructionIter<'a> {
    type Item = Result<DeltaInstructionView<'a>, DeltaError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count_remaining == 0 {
            if !self.remaining.is_empty() {
                let trailing = self.remaining.len();
                self.remaining = &[];
                return Some(Err(DeltaError::TrailingBytes(trailing)));
            }
            return None;
        }

        if self.remaining.is_empty() {
            self.count_remaining = 0;
            return Some(Err(DeltaError::Truncated { needed: 1, have: 0 }));
        }

        let tag = self.remaining[0];
        let mut cursor = 1;
        self.count_remaining -= 1;

        match tag {
            0 => {
                let (offset, u1) = match decode_varint(&self.remaining[cursor..]) {
                    Ok(res) => res,
                    Err(e) => return Some(Err(DeltaError::Varint(e))),
                };
                cursor += u1;
                let (len, u2) = match decode_varint(&self.remaining[cursor..]) {
                    Ok(res) => res,
                    Err(e) => return Some(Err(DeltaError::Varint(e))),
                };
                cursor += u2;
                if len == 0 {
                    return Some(Err(DeltaError::ZeroLengthInstruction));
                }
                self.remaining = &self.remaining[cursor..];
                Some(Ok(DeltaInstructionView::Copy { offset, len }))
            }
            1 => {
                let (slice, used) =
                    match decode_len_prefixed(&self.remaining[cursor..], MAX_DELTA_TARGET_BYTES) {
                        Ok(res) => res,
                        Err(e) => return Some(Err(DeltaError::Varint(e))),
                    };
                cursor += used;
                if slice.is_empty() {
                    return Some(Err(DeltaError::ZeroLengthInstruction));
                }
                self.remaining = &self.remaining[cursor..];
                Some(Ok(DeltaInstructionView::Insert(slice)))
            }
            2 => {
                let (len, u1) = match decode_varint(&self.remaining[cursor..]) {
                    Ok(res) => res,
                    Err(e) => return Some(Err(DeltaError::Varint(e))),
                };
                cursor += u1;
                if len == 0 {
                    return Some(Err(DeltaError::ZeroLengthInstruction));
                }
                if cursor >= self.remaining.len() {
                    return Some(Err(DeltaError::Truncated {
                        needed: cursor + 1,
                        have: self.remaining.len(),
                    }));
                }
                let byte = self.remaining[cursor];
                cursor += 1;
                self.remaining = &self.remaining[cursor..];
                Some(Ok(DeltaInstructionView::Run { len, byte }))
            }
            other => Some(Err(DeltaError::InvalidInstructionTag(other))),
        }
    }
}

/// The kind of operation a delta records (Spec 0007 / Spec 0010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeltaOpKind {
    /// A file was created or overwritten.
    Write,
    /// A file was deleted.
    Delete,
    /// A file was renamed or moved.
    Rename,
    /// A tool call was executed.
    ToolCall,
    /// A prompt or reasoning turn was recorded.
    Prompt,
}

impl DeltaOpKind {
    /// Convert to the canonical 3-bit wire discriminant.
    pub const fn to_wire_code(self) -> u8 {
        match self {
            Self::Write => 0,
            Self::Delete => 1,
            Self::Rename => 2,
            Self::ToolCall => 3,
            Self::Prompt => 4,
        }
    }

    /// Decode from the canonical 3-bit wire discriminant.
    pub const fn from_wire_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Write),
            1 => Some(Self::Delete),
            2 => Some(Self::Rename),
            3 => Some(Self::ToolCall),
            4 => Some(Self::Prompt),
            _ => None,
        }
    }
}

#[inline]
const fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Pack a 64-character lowercase hex string into 32 raw bytes (`None` if not 64-char lower-hex).
#[inline]
pub fn try_pack_lower_hex_32(s: &str) -> Option<[u8; 32]> {
    let raw = s.as_bytes();
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        let hi = lower_hex_nibble(raw[i * 2])?;
        let lo = lower_hex_nibble(raw[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(out)
}

/// Unpack 32 raw bytes into a 64-character lowercase hex string.
#[inline]
pub fn unpack_lower_hex_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0F) as usize]);
    }
    // Safety: only ASCII hex chars were pushed.
    unsafe { String::from_utf8_unchecked(out) }
}

/// Representation of a run hash in an `"SCDS"` delta stream frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunHashWire<'a> {
    /// 32 raw bytes of a packed 64-character lowercase hex digest.
    Packed(&'a [u8; 32]),
    /// UTF-8 string format.
    String(&'a str),
}

impl<'a> RunHashWire<'a> {
    /// Convert or unpack this run hash into an owned 64-character lowercase hex string or UTF-8 string.
    pub fn to_string_repr(&self) -> String {
        match self {
            Self::Packed(raw) => unpack_lower_hex_32(raw),
            Self::String(s) => (*s).to_owned(),
        }
    }

    /// Check if this run hash matches the given hex or string.
    pub fn matches(&self, other: &str) -> bool {
        match self {
            Self::Packed(raw) => {
                if let Some(packed) = try_pack_lower_hex_32(other) {
                    *raw == &packed
                } else {
                    false
                }
            }
            Self::String(s) => *s == other,
        }
    }
}

/// Borrowed representation of one custody operation delta in an `"SCDS"` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpDeltaView<'a> {
    /// Sequence identifier of this delta.
    pub seq: u64,
    /// Operation discriminant.
    pub kind: DeltaOpKind,
    /// Borrowed path string (from path table).
    pub path: Option<&'a str>,
    /// Borrowed prompt turn ID (from turn table).
    pub prompt_turn_id: Option<&'a str>,
    /// Raw 32-byte content hash if packed, or None.
    pub content_hash_packed: Option<&'a [u8; 32]>,
    /// Borrowed string content hash if unpacked, or None.
    pub content_hash_str: Option<&'a str>,
    /// Millisecond-precision UNIX timestamp.
    pub timestamp_millis: i64,
    /// Sub-millisecond remainder in nanoseconds.
    pub timestamp_nanos: u32,
}

impl<'a> OpDeltaView<'a> {
    /// Return the content hash as an owned string, unpacking packed hex if needed.
    pub fn content_hash_to_string(&self) -> Option<String> {
        if let Some(packed) = self.content_hash_packed {
            Some(unpack_lower_hex_32(packed))
        } else {
            self.content_hash_str.map(str::to_owned)
        }
    }
}

/// Zero-copy borrowed view over an `"SCDS"` structured delta stream frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaStreamView<'a> {
    /// Borrowed or unpacked run hash representation.
    pub run_hash: RunHashWire<'a>,
    /// String table for paths.
    pub path_table: Vec<&'a str>,
    /// String table for prompt turn IDs.
    pub turn_table: Vec<&'a str>,
    /// Number of deltas in the stream.
    pub delta_count: usize,
    raw_deltas: &'a [u8],
}

impl<'a> DeltaStreamView<'a> {
    /// Parse the header and interned tables of an `"SCDS"` binary wire frame without allocations.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DeltaError> {
        const MIN_HEADER: usize = 4 + 1 + 1;
        if bytes.len() < MIN_HEADER {
            return Err(DeltaError::Truncated {
                needed: MIN_HEADER,
                have: bytes.len(),
            });
        }
        if bytes[0..4] != DELTA_STREAM_MAGIC {
            return Err(DeltaError::MagicMismatch([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ]));
        }
        if bytes[4] != DELTA_STREAM_VERSION {
            return Err(DeltaError::UnsupportedVersion(bytes[4]));
        }

        let mut cursor = 5;
        let run_flag = bytes[cursor];
        cursor += 1;
        let run_hash = match run_flag {
            1 => {
                if bytes.len().saturating_sub(cursor) < 32 {
                    return Err(DeltaError::Truncated {
                        needed: cursor + 32,
                        have: bytes.len(),
                    });
                }
                let raw: &'a [u8; 32] = bytes[cursor..cursor + 32].try_into().unwrap();
                cursor += 32;
                RunHashWire::Packed(raw)
            }
            0 => {
                let (slice, used) = decode_len_prefixed(&bytes[cursor..], 256)?;
                cursor += used;
                let s = std::str::from_utf8(slice)
                    .map_err(|_| DeltaError::InvalidEncoding("run_hash"))?;
                RunHashWire::String(s)
            }
            other => return Err(DeltaError::InvalidDiscriminant("run_flag", other)),
        };

        let (path_count_u64, used) = decode_varint(&bytes[cursor..])?;
        cursor += used;
        let path_count =
            usize::try_from(path_count_u64).map_err(|_| DeltaError::CountExceedsFrame {
                count: usize::MAX,
                remaining: 0,
            })?;
        if path_count > bytes.len().saturating_sub(cursor) {
            return Err(DeltaError::CountExceedsFrame {
                count: path_count,
                remaining: bytes.len().saturating_sub(cursor),
            });
        }
        let mut path_table = Vec::with_capacity(path_count);
        for _ in 0..path_count {
            let (slice, used) = decode_len_prefixed(&bytes[cursor..], 4096)?;
            cursor += used;
            let s = std::str::from_utf8(slice)
                .map_err(|_| DeltaError::InvalidEncoding("path_table"))?;
            path_table.push(s);
        }

        let (turn_count_u64, used) = decode_varint(&bytes[cursor..])?;
        cursor += used;
        let turn_count =
            usize::try_from(turn_count_u64).map_err(|_| DeltaError::CountExceedsFrame {
                count: usize::MAX,
                remaining: 0,
            })?;
        if turn_count > bytes.len().saturating_sub(cursor) {
            return Err(DeltaError::CountExceedsFrame {
                count: turn_count,
                remaining: bytes.len().saturating_sub(cursor),
            });
        }
        let mut turn_table = Vec::with_capacity(turn_count);
        for _ in 0..turn_count {
            let (slice, used) = decode_len_prefixed(&bytes[cursor..], 512)?;
            cursor += used;
            let s = std::str::from_utf8(slice)
                .map_err(|_| DeltaError::InvalidEncoding("turn_table"))?;
            turn_table.push(s);
        }

        let (delta_count_u64, used) = decode_varint(&bytes[cursor..])?;
        cursor += used;
        let delta_count =
            usize::try_from(delta_count_u64).map_err(|_| DeltaError::CountExceedsFrame {
                count: usize::MAX,
                remaining: 0,
            })?;
        if delta_count > bytes.len().saturating_sub(cursor) {
            return Err(DeltaError::CountExceedsFrame {
                count: delta_count,
                remaining: bytes.len().saturating_sub(cursor),
            });
        }

        Ok(Self {
            run_hash,
            path_table,
            turn_table,
            delta_count,
            raw_deltas: &bytes[cursor..],
        })
    }

    /// Iterate over borrowed operation deltas in the stream.
    pub fn iter_deltas<'b>(&'b self) -> DeltaStreamIter<'a, 'b> {
        DeltaStreamIter {
            view: self,
            remaining: self.raw_deltas,
            count_remaining: self.delta_count,
            index: 0,
            prev_seq: 0,
            prev_ts_ms: 0,
            prev_dt_ms: 0,
        }
    }
}

/// Zero-copy iterator over operations in a structured delta stream.
pub struct DeltaStreamIter<'a, 'b> {
    view: &'b DeltaStreamView<'a>,
    remaining: &'a [u8],
    count_remaining: usize,
    index: usize,
    prev_seq: u64,
    prev_ts_ms: i64,
    prev_dt_ms: i64,
}

impl<'a, 'b> Iterator for DeltaStreamIter<'a, 'b> {
    type Item = Result<OpDeltaView<'a>, DeltaError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count_remaining == 0 {
            if !self.remaining.is_empty() {
                let trailing = self.remaining.len();
                self.remaining = &[];
                return Some(Err(DeltaError::TrailingBytes(trailing)));
            }
            return None;
        }

        if self.remaining.is_empty() {
            self.count_remaining = 0;
            return Some(Err(DeltaError::Truncated { needed: 1, have: 0 }));
        }

        let mut cursor = 0;
        let (seq_delta, u_seq) = match decode_varint(&self.remaining[cursor..]) {
            Ok(res) => res,
            Err(e) => return Some(Err(DeltaError::Varint(e))),
        };
        cursor += u_seq;

        let seq = if self.index == 0 {
            seq_delta
        } else {
            if seq_delta == 0 {
                return Some(Err(DeltaError::NonMonotonicSeq {
                    seq: self.prev_seq,
                    prev: self.prev_seq,
                }));
            }
            match self.prev_seq.checked_add(seq_delta) {
                Some(s) => s,
                None => {
                    return Some(Err(DeltaError::NonMonotonicSeq {
                        seq: u64::MAX,
                        prev: self.prev_seq,
                    }));
                }
            }
        };
        self.prev_seq = seq;

        if cursor >= self.remaining.len() {
            return Some(Err(DeltaError::Truncated {
                needed: cursor + 1,
                have: self.remaining.len(),
            }));
        }
        let flags = self.remaining[cursor];
        cursor += 1;

        if (flags & 0x80 != 0) && (flags & 0x10 == 0) {
            return Some(Err(DeltaError::InvalidEncoding(
                "content_hash 0x80 without 0x10",
            )));
        }

        let kind = match DeltaOpKind::from_wire_code(flags & 0x07) {
            Some(k) => k,
            None => return Some(Err(DeltaError::InvalidDiscriminant("OpKind", flags & 0x07))),
        };

        let path = if flags & 0x08 != 0 {
            let (path_idx_u64, u_pi) = match decode_varint(&self.remaining[cursor..]) {
                Ok(res) => res,
                Err(e) => return Some(Err(DeltaError::Varint(e))),
            };
            cursor += u_pi;
            let path_idx = path_idx_u64 as usize;
            match self.view.path_table.get(path_idx) {
                Some(&p) => Some(p),
                None => {
                    return Some(Err(DeltaError::CountExceedsFrame {
                        count: path_idx,
                        remaining: self.view.path_table.len(),
                    }));
                }
            }
        } else {
            None
        };

        let (content_hash_packed, content_hash_str) = if flags & 0x10 != 0 {
            if flags & 0x80 != 0 {
                if self.remaining.len().saturating_sub(cursor) < 32 {
                    return Some(Err(DeltaError::Truncated {
                        needed: cursor + 32,
                        have: self.remaining.len(),
                    }));
                }
                let raw: &'a [u8; 32] = self.remaining[cursor..cursor + 32].try_into().unwrap();
                cursor += 32;
                (Some(raw), None)
            } else {
                let (raw_ch, u_ch) = match decode_len_prefixed(&self.remaining[cursor..], 256) {
                    Ok(res) => res,
                    Err(e) => return Some(Err(DeltaError::Varint(e))),
                };
                cursor += u_ch;
                let s = match std::str::from_utf8(raw_ch) {
                    Ok(s) => s,
                    Err(_) => return Some(Err(DeltaError::InvalidEncoding("content_hash"))),
                };
                (None, Some(s))
            }
        } else {
            (None, None)
        };

        let prompt_turn_id = if flags & 0x20 != 0 {
            let (turn_idx_u64, u_ti) = match decode_varint(&self.remaining[cursor..]) {
                Ok(res) => res,
                Err(e) => return Some(Err(DeltaError::Varint(e))),
            };
            cursor += u_ti;
            let turn_idx = turn_idx_u64 as usize;
            match self.view.turn_table.get(turn_idx) {
                Some(&pt) => Some(pt),
                None => {
                    return Some(Err(DeltaError::CountExceedsFrame {
                        count: turn_idx,
                        remaining: self.view.turn_table.len(),
                    }));
                }
            }
        } else {
            None
        };

        let ts_ms = if self.index == 0 {
            let (t0, u_t) = match decode_signed_varint(&self.remaining[cursor..]) {
                Ok(res) => res,
                Err(e) => return Some(Err(DeltaError::Varint(e))),
            };
            cursor += u_t;
            t0
        } else if self.index == 1 {
            let (dt, u_t) = match decode_signed_varint(&self.remaining[cursor..]) {
                Ok(res) => res,
                Err(e) => return Some(Err(DeltaError::Varint(e))),
            };
            cursor += u_t;
            self.prev_dt_ms = dt;
            match self.prev_ts_ms.checked_add(dt) {
                Some(t) => t,
                None => return Some(Err(DeltaError::TimestampOverflow("dt overflow"))),
            }
        } else {
            let (dod, u_t) = match decode_signed_varint(&self.remaining[cursor..]) {
                Ok(res) => res,
                Err(e) => return Some(Err(DeltaError::Varint(e))),
            };
            cursor += u_t;
            let dt = match self.prev_dt_ms.checked_add(dod) {
                Some(d) => d,
                None => return Some(Err(DeltaError::TimestampOverflow("dod overflow"))),
            };
            self.prev_dt_ms = dt;
            match self.prev_ts_ms.checked_add(dt) {
                Some(t) => t,
                None => return Some(Err(DeltaError::TimestampOverflow("dt overflow"))),
            }
        };
        self.prev_ts_ms = ts_ms;

        let timestamp_nanos = if flags & 0x40 != 0 {
            let (nanos_u64, u_n) = match decode_varint(&self.remaining[cursor..]) {
                Ok(res) => res,
                Err(e) => return Some(Err(DeltaError::Varint(e))),
            };
            cursor += u_n;
            nanos_u64 as u32
        } else {
            0
        };

        self.remaining = &self.remaining[cursor..];
        self.count_remaining -= 1;
        self.index += 1;

        Some(Ok(OpDeltaView {
            seq,
            kind,
            path,
            prompt_turn_id,
            content_hash_packed,
            content_hash_str,
            timestamp_millis: ts_ms,
            timestamp_nanos,
        }))
    }
}

/// Owned structured custody delta stream (`"SCDS"` v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaStream {
    /// Identifier for the execution run.
    pub run_hash: String,
    /// Ordered list of operation-level deltas in this stream.
    pub deltas: Vec<OpDelta>,
}

/// Owned representation of an operation-level delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpDelta {
    /// Sequence identifier (strictly increasing).
    pub seq: u64,
    /// Operation kind.
    pub kind: DeltaOpKind,
    /// Target path (if any).
    pub path: Option<String>,
    /// Associated prompt turn ID (if any).
    pub prompt_turn_id: Option<String>,
    /// Resulting content hash (if any).
    pub content_hash: Option<String>,
    /// Millisecond-precision UNIX timestamp.
    pub timestamp_millis: i64,
    /// Sub-millisecond remainder in nanoseconds.
    pub timestamp_nanos: u32,
}

impl DeltaStream {
    /// Encode this [`DeltaStream`] into the compact `"SCDS"` binary wire format.
    pub fn encode_delta_wire(&self) -> Result<Vec<u8>, DeltaError> {
        let mut path_table = Vec::new();
        let mut path_indices = std::collections::BTreeMap::new();
        for d in &self.deltas {
            if let Some(p) = &d.path
                && !path_indices.contains_key(p)
            {
                path_indices.insert(p.clone(), path_table.len());
                path_table.push(p.clone());
            }
        }

        let mut turn_table = Vec::new();
        let mut turn_indices = std::collections::BTreeMap::new();
        for d in &self.deltas {
            if let Some(pt) = &d.prompt_turn_id
                && !turn_indices.contains_key(pt)
            {
                turn_indices.insert(pt.clone(), turn_table.len());
                turn_table.push(pt.clone());
            }
        }

        let mut buf = Vec::with_capacity(64 + self.deltas.len() * 38);
        buf.extend_from_slice(&DELTA_STREAM_MAGIC);
        buf.push(DELTA_STREAM_VERSION);

        if let Some(packed_run) = try_pack_lower_hex_32(&self.run_hash) {
            buf.push(1);
            buf.extend_from_slice(&packed_run);
        } else {
            buf.push(0);
            encode_len_prefixed(self.run_hash.as_bytes(), &mut buf)?;
        }

        encode_varint(path_table.len() as u64, &mut buf)?;
        for p in &path_table {
            encode_len_prefixed(p.as_bytes(), &mut buf)?;
        }

        encode_varint(turn_table.len() as u64, &mut buf)?;
        for t in &turn_table {
            encode_len_prefixed(t.as_bytes(), &mut buf)?;
        }

        encode_varint(self.deltas.len() as u64, &mut buf)?;

        let mut prev_seq = 0u64;
        let mut prev_ts_ms = 0i64;
        let mut prev_dt_ms = 0i64;

        for (i, d) in self.deltas.iter().enumerate() {
            let seq_delta = if i == 0 {
                d.seq
            } else {
                if d.seq <= prev_seq {
                    return Err(DeltaError::NonMonotonicSeq {
                        seq: d.seq,
                        prev: prev_seq,
                    });
                }
                d.seq - prev_seq
            };
            prev_seq = d.seq;
            encode_varint(seq_delta, &mut buf)?;

            let packed_ch = d.content_hash.as_deref().and_then(try_pack_lower_hex_32);

            let mut flags = d.kind.to_wire_code() & 0x07;
            if d.path.is_some() {
                flags |= 0x08;
            }
            if d.content_hash.is_some() {
                flags |= 0x10;
            }
            if d.prompt_turn_id.is_some() {
                flags |= 0x20;
            }
            if d.timestamp_nanos != 0 {
                flags |= 0x40;
            }
            if packed_ch.is_some() {
                flags |= 0x80;
            }
            buf.push(flags);

            if let Some(p) = &d.path {
                let idx = path_indices.get(p).copied().unwrap_or(0);
                encode_varint(idx as u64, &mut buf)?;
            }
            if let Some(raw32) = packed_ch {
                buf.extend_from_slice(&raw32);
            } else if let Some(ch) = &d.content_hash {
                encode_len_prefixed(ch.as_bytes(), &mut buf)?;
            }
            if let Some(pt) = &d.prompt_turn_id {
                let idx = turn_indices.get(pt).copied().unwrap_or(0);
                encode_varint(idx as u64, &mut buf)?;
            }

            let ts_ms = d.timestamp_millis;
            if i == 0 {
                encode_signed_varint(ts_ms, &mut buf)?;
            } else if i == 1 {
                let dt = ts_ms
                    .checked_sub(prev_ts_ms)
                    .ok_or(DeltaError::TimestampOverflow("timestamp delta overflow"))?;
                encode_signed_varint(dt, &mut buf)?;
                prev_dt_ms = dt;
            } else {
                let dt = ts_ms
                    .checked_sub(prev_ts_ms)
                    .ok_or(DeltaError::TimestampOverflow("timestamp delta overflow"))?;
                let dod = dt
                    .checked_sub(prev_dt_ms)
                    .ok_or(DeltaError::TimestampOverflow(
                        "timestamp delta-of-delta overflow",
                    ))?;
                encode_signed_varint(dod, &mut buf)?;
                prev_dt_ms = dt;
            }
            prev_ts_ms = ts_ms;

            if d.timestamp_nanos != 0 {
                encode_varint(d.timestamp_nanos as u64, &mut buf)?;
            }
        }

        Ok(buf)
    }

    /// Decode a [`DeltaStream`] from an `"SCDS"` binary wire frame.
    pub fn decode_delta_wire(bytes: &[u8]) -> Result<Self, DeltaError> {
        let view = DeltaStreamView::parse(bytes)?;
        let run_hash = view.run_hash.to_string_repr();
        let mut deltas = Vec::with_capacity(view.delta_count);
        for item in view.iter_deltas() {
            let op_view = item?;
            deltas.push(OpDelta {
                seq: op_view.seq,
                kind: op_view.kind,
                path: op_view.path.map(str::to_owned),
                prompt_turn_id: op_view.prompt_turn_id.map(str::to_owned),
                content_hash: op_view.content_hash_to_string(),
                timestamp_millis: op_view.timestamp_millis,
                timestamp_nanos: op_view.timestamp_nanos,
            });
        }
        Ok(Self { run_hash, deltas })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMMY_BASE_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";
    const DUMMY_TARGET_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000000002";

    #[test]
    fn scdp_round_trip_identical_blobs() {
        let data = b"identical content across base and target in CAS storage";
        let patch = CasDeltaPatch::compute(data, data, DUMMY_BASE_HASH, DUMMY_TARGET_HASH);
        assert_eq!(patch.instructions.len(), 1);
        assert_eq!(
            patch.instructions[0],
            DeltaInstruction::Copy {
                offset: 0,
                len: data.len() as u64
            }
        );

        let wire = patch.encode_wire().expect("wire encoding");
        let decoded = CasDeltaPatch::decode_wire(&wire).expect("wire decoding");
        assert_eq!(patch, decoded);

        let reconstructed = decoded.apply(data).expect("apply");
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn scdp_round_trip_with_insert_run_copy() {
        let base = b"AAAABBBBCCCCDDDD01234567890123456789ZZZZ";
        let mut target = Vec::new();
        target.extend_from_slice(b"PREFIX--"); // insert
        target.extend_from_slice(b"01234567890123456789"); // copy from base
        target.extend_from_slice(&[0xFF; 32]); // run
        target.extend_from_slice(b"--SUFFIX"); // insert

        let patch = CasDeltaPatch::compute(base, &target, DUMMY_BASE_HASH, DUMMY_TARGET_HASH);
        let wire = patch.encode_wire().expect("encode");

        // Test zero-copy view parsing
        let view = CasDeltaPatchView::parse(&wire).expect("view parse");
        assert_eq!(view.base_digest, DUMMY_BASE_HASH);
        assert_eq!(view.target_digest, DUMMY_TARGET_HASH);
        assert_eq!(view.target_size, target.len() as u64);

        // Apply via view without materializing instructions
        let reconstructed = view.apply(base).expect("view apply");
        assert_eq!(reconstructed, target);

        // Apply via owned struct
        let owned = CasDeltaPatch::decode_wire(&wire).expect("owned decode");
        let owned_rec = owned.apply(base).expect("owned apply");
        assert_eq!(owned_rec, target);
    }

    #[test]
    fn scdp_view_iter_borrowed_slices() {
        let base = b"12345678abcdefgh";
        let target = b"12345678INSERTED_BYTESabcdefgh";
        let patch = CasDeltaPatch::compute(base, target, DUMMY_BASE_HASH, DUMMY_TARGET_HASH);
        let wire = patch.encode_wire().unwrap();

        let view = CasDeltaPatchView::parse(&wire).unwrap();
        let insts: Vec<_> = view.iter_instructions().collect::<Result<_, _>>().unwrap();
        assert!(
            insts
                .iter()
                .any(|i| matches!(i, DeltaInstructionView::Insert(b"INSERTED_BYTES")))
        );
    }

    #[test]
    fn scdp_negative_controls() {
        let base = b"sample base buffer";
        let target = b"sample target buffer";
        let patch = CasDeltaPatch::compute(base, target, DUMMY_BASE_HASH, DUMMY_TARGET_HASH);
        let wire = patch.encode_wire().unwrap();

        // 1. Bad magic
        let mut bad_magic = wire.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            CasDeltaPatchView::parse(&bad_magic),
            Err(DeltaError::MagicMismatch(_))
        ));

        // 2. Unsupported version
        let mut bad_ver = wire.clone();
        bad_ver[4] = 99;
        assert!(matches!(
            CasDeltaPatchView::parse(&bad_ver),
            Err(DeltaError::UnsupportedVersion(99))
        ));

        // 3. Truncated header
        assert!(matches!(
            CasDeltaPatchView::parse(&wire[..20]),
            Err(DeltaError::Truncated { .. })
        ));

        // 4. Trailing unparsed bytes
        let mut trailing = wire.clone();
        trailing.push(0xFE);
        let view = CasDeltaPatchView::parse(&trailing).unwrap();
        let mut found_trailing = false;
        for res in view.iter_instructions() {
            if let Err(e) = res {
                assert!(matches!(e, DeltaError::TrailingBytes(1)));
                found_trailing = true;
                break;
            }
        }
        assert!(found_trailing);
    }

    #[test]
    fn scds_round_trip_owned_and_view() {
        let run_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let content_hash = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

        let stream = DeltaStream {
            run_hash: run_hash.to_string(),
            deltas: vec![
                OpDelta {
                    seq: 1,
                    kind: DeltaOpKind::Write,
                    path: Some("crates/scorcher-core/src/lib.rs".to_string()),
                    prompt_turn_id: Some("turn-001".to_string()),
                    content_hash: Some(content_hash.to_string()),
                    timestamp_millis: 1700000000000,
                    timestamp_nanos: 123456,
                },
                OpDelta {
                    seq: 2,
                    kind: DeltaOpKind::Delete,
                    path: Some("crates/scorcher-core/src/legacy.rs".to_string()),
                    prompt_turn_id: Some("turn-001".to_string()),
                    content_hash: None,
                    timestamp_millis: 1700000000050,
                    timestamp_nanos: 0,
                },
                OpDelta {
                    seq: 5,
                    kind: DeltaOpKind::ToolCall,
                    path: None,
                    prompt_turn_id: Some("turn-002".to_string()),
                    content_hash: Some("non-hex-custom-digest".to_string()),
                    timestamp_millis: 1700000000120,
                    timestamp_nanos: 654321,
                },
            ],
        };

        let wire = stream.encode_delta_wire().expect("encode_delta_wire");

        // Parse zero-copy view
        let view = DeltaStreamView::parse(&wire).expect("DeltaStreamView::parse");
        assert!(view.run_hash.matches(run_hash));
        assert_eq!(view.delta_count, 3);
        assert_eq!(view.path_table.len(), 2);
        assert_eq!(view.turn_table.len(), 2);

        let mut iter = view.iter_deltas();

        let op1 = iter.next().unwrap().unwrap();
        assert_eq!(op1.seq, 1);
        assert_eq!(op1.kind, DeltaOpKind::Write);
        assert_eq!(op1.path, Some("crates/scorcher-core/src/lib.rs"));
        assert_eq!(op1.prompt_turn_id, Some("turn-001"));
        assert_eq!(op1.content_hash_to_string(), Some(content_hash.to_string()));
        assert_eq!(op1.timestamp_millis, 1700000000000);
        assert_eq!(op1.timestamp_nanos, 123456);

        let op2 = iter.next().unwrap().unwrap();
        assert_eq!(op2.seq, 2);
        assert_eq!(op2.kind, DeltaOpKind::Delete);
        assert_eq!(op2.path, Some("crates/scorcher-core/src/legacy.rs"));
        assert_eq!(op2.prompt_turn_id, Some("turn-001"));
        assert_eq!(op2.content_hash_to_string(), None);
        assert_eq!(op2.timestamp_millis, 1700000000050);
        assert_eq!(op2.timestamp_nanos, 0);

        let op3 = iter.next().unwrap().unwrap();
        assert_eq!(op3.seq, 5);
        assert_eq!(op3.kind, DeltaOpKind::ToolCall);
        assert_eq!(op3.path, None);
        assert_eq!(op3.prompt_turn_id, Some("turn-002"));
        assert_eq!(
            op3.content_hash_to_string(),
            Some("non-hex-custom-digest".to_string())
        );
        assert_eq!(op3.timestamp_millis, 1700000000120);
        assert_eq!(op3.timestamp_nanos, 654321);

        assert!(iter.next().is_none());

        // Decode into owned struct
        let decoded =
            DeltaStream::decode_delta_wire(&wire).expect("DeltaStream::decode_delta_wire");
        assert_eq!(stream, decoded);
    }

    #[test]
    fn scds_negative_controls() {
        let stream = DeltaStream {
            run_hash: "run-custom-string-format".to_string(),
            deltas: vec![
                OpDelta {
                    seq: 1,
                    kind: DeltaOpKind::Prompt,
                    path: None,
                    prompt_turn_id: None,
                    content_hash: None,
                    timestamp_millis: 1000,
                    timestamp_nanos: 0,
                },
                OpDelta {
                    seq: 2,
                    kind: DeltaOpKind::Rename,
                    path: Some("file.txt".to_string()),
                    prompt_turn_id: None,
                    content_hash: None,
                    timestamp_millis: 1010,
                    timestamp_nanos: 0,
                },
            ],
        };

        let wire = stream.encode_delta_wire().expect("encode_wire");

        // 1. Bad magic
        let mut bad_magic = wire.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            DeltaStreamView::parse(&bad_magic),
            Err(DeltaError::MagicMismatch(_))
        ));

        // 2. Unsupported version
        let mut bad_ver = wire.clone();
        bad_ver[4] = 99;
        assert!(matches!(
            DeltaStreamView::parse(&bad_ver),
            Err(DeltaError::UnsupportedVersion(99))
        ));

        // 3. Truncated
        assert!(matches!(
            DeltaStreamView::parse(&wire[..5]),
            Err(DeltaError::Truncated { .. })
        ));

        // 4. Non-monotonic sequences
        let non_monotonic = DeltaStream {
            run_hash: "run-test".to_string(),
            deltas: vec![
                OpDelta {
                    seq: 5,
                    kind: DeltaOpKind::Prompt,
                    path: None,
                    prompt_turn_id: None,
                    content_hash: None,
                    timestamp_millis: 1000,
                    timestamp_nanos: 0,
                },
                OpDelta {
                    seq: 3, // <= prev_seq
                    kind: DeltaOpKind::Prompt,
                    path: None,
                    prompt_turn_id: None,
                    content_hash: None,
                    timestamp_millis: 1010,
                    timestamp_nanos: 0,
                },
            ],
        };
        assert!(matches!(
            non_monotonic.encode_delta_wire(),
            Err(DeltaError::NonMonotonicSeq { .. })
        ));
    }
}
