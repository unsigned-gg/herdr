// Derived from cerebral-work/scorcher, crates/scorcher-core/src/delta.rs at e14b933
// (Spec 0007, REQ-0007-04). Licensor of the source: 2die4 Inc. / Christian Todie
// (BUSL-1.1, Change License 0BSD). First-party code, not part of upstream rust-shed.

//! RFC 9000 section 16 variable-length integers and signed ZigZag.
//!
//! A varint holds an integer in `0..=MAX_VARINT` (`2^62 - 1`) in 1, 2, 4 or 8
//! bytes. The top two bits of the first byte give the width (`1 << (b0 >> 6)`).
//! This has no per-byte continuation branch, unlike LEB128.
//!
//! The decoder accepts a value that uses more bytes than it needs, as RFC 9000
//! allows. The encoder always uses the shortest form.

use std::fmt;

/// Largest value a varint can hold: `2^62 - 1`.
pub const MAX_VARINT: u64 = (1 << 62) - 1;

/// Largest size of one varint, in bytes.
pub const MAX_VARINT_BYTES: usize = 8;

/// Why a varint operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarintError {
    /// The value is larger than [`MAX_VARINT`].
    TooLarge(u64),
    /// A signed value is outside the range that ZigZag maps into [`MAX_VARINT`].
    SignedOutOfRange(i64),
    /// The input ended before the varint did.
    Truncated {
        /// Bytes the first byte asks for.
        needed: usize,
        /// Bytes that were in the input.
        have: usize,
    },
    /// A length prefix is larger than the caller allows.
    LengthOverLimit {
        /// The declared length.
        len: u64,
        /// The limit the caller gave.
        max: usize,
    },
}

impl fmt::Display for VarintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(v) => {
                write!(f, "value {v} is larger than the varint maximum {MAX_VARINT}")
            },
            Self::SignedOutOfRange(v) => {
                write!(f, "signed value {v} is outside the ZigZag varint range")
            },
            Self::Truncated { needed, have } => {
                write!(f, "varint needs {needed} bytes, input has {have}")
            },
            Self::LengthOverLimit { len, max } => {
                write!(f, "length {len} is larger than the limit {max}")
            },
        }
    }
}

impl std::error::Error for VarintError {}

/// Append `val` to `out` as a varint. Returns the bytes written (1, 2, 4 or 8).
///
/// # Errors
/// [`VarintError::TooLarge`] when `val > MAX_VARINT`. `out` is not changed.
pub fn encode_varint(val: u64, out: &mut Vec<u8>) -> Result<usize, VarintError> {
    if val <= 63 {
        out.push(val as u8);
        Ok(1)
    } else if val <= 16_383 {
        out.extend_from_slice(&((val as u16) | (0b01 << 14)).to_be_bytes());
        Ok(2)
    } else if val <= 1_073_741_823 {
        out.extend_from_slice(&((val as u32) | (0b10 << 30)).to_be_bytes());
        Ok(4)
    } else if val <= MAX_VARINT {
        out.extend_from_slice(&(val | (0b11 << 62)).to_be_bytes());
        Ok(8)
    } else {
        Err(VarintError::TooLarge(val))
    }
}

/// Read one varint from the front of `buf`. Returns `(value, bytes_used)`.
///
/// # Errors
/// [`VarintError::Truncated`] when `buf` is empty or shorter than the first
/// byte asks for.
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), VarintError> {
    let Some(&first) = buf.first() else {
        return Err(VarintError::Truncated { needed: 1, have: 0 });
    };
    let width = 1usize << (first >> 6);
    let Some(bytes) = buf.get(..width) else {
        return Err(VarintError::Truncated { needed: width, have: buf.len() });
    };
    // Fold the bytes big-endian; the two prefix bits are masked off the first.
    let val = bytes[1..]
        .iter()
        .fold(u64::from(first & 0x3f), |acc, &b| (acc << 8) | u64::from(b));
    Ok((val, width))
}

/// Map a signed integer to an unsigned one: `0, -1, 1, -2, 2` become `0, 1, 2, 3, 4`.
#[must_use]
pub const fn zigzag_encode(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

/// Invert [`zigzag_encode`].
#[must_use]
pub const fn zigzag_decode(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}

/// ZigZag `n` and append it as a varint. Returns the bytes written.
///
/// # Errors
/// [`VarintError::SignedOutOfRange`] when the ZigZag value is larger than
/// [`MAX_VARINT`]. `out` is not changed.
pub fn encode_signed_varint(n: i64, out: &mut Vec<u8>) -> Result<usize, VarintError> {
    encode_varint(zigzag_encode(n), out).map_err(|_| VarintError::SignedOutOfRange(n))
}

/// Read one varint from the front of `buf` and undo the ZigZag.
///
/// # Errors
/// The same as [`decode_varint`].
pub fn decode_signed_varint(buf: &[u8]) -> Result<(i64, usize), VarintError> {
    let (zz, used) = decode_varint(buf)?;
    Ok((zigzag_decode(zz), used))
}

/// Append `bytes` to `out`, after a varint with their length.
///
/// # Errors
/// [`VarintError::TooLarge`] when the length is larger than [`MAX_VARINT`].
/// `out` is not changed.
pub fn encode_len_prefixed(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), VarintError> {
    encode_varint(bytes.len() as u64, out)?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// Read a length-prefixed slice from the front of `buf`.
/// Returns `(slice, bytes_used)`, where `bytes_used` includes the prefix.
///
/// # Errors
/// [`VarintError::LengthOverLimit`] when the length is larger than `max_len`.
/// [`VarintError::Truncated`] when `buf` is shorter than the prefix declares.
pub fn decode_len_prefixed(buf: &[u8], max_len: usize) -> Result<(&[u8], usize), VarintError> {
    let (len, prefix) = decode_varint(buf)?;
    let len_usize = usize::try_from(len)
        .ok()
        .filter(|&l| l <= max_len)
        .ok_or(VarintError::LengthOverLimit { len, max: max_len })?;
    let end = prefix
        .checked_add(len_usize)
        .ok_or(VarintError::LengthOverLimit { len, max: max_len })?;
    let Some(slice) = buf.get(prefix..end) else {
        return Err(VarintError::Truncated { needed: end, have: buf.len() });
    };
    Ok((slice, end))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_width_tier_round_trips_and_a_short_input_fails() {
        let cases = [
            (0u64, 1usize),
            (1, 1),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (MAX_VARINT, 8),
        ];
        let mut buf = Vec::new();
        for (val, width) in cases {
            buf.clear();
            assert_eq!(encode_varint(val, &mut buf).unwrap(), width, "val={val}");
            assert_eq!(buf.len(), width);
            assert_eq!(decode_varint(&buf).unwrap(), (val, width));
            assert_eq!(
                decode_varint(&buf[..width - 1]),
                if width == 1 {
                    Err(VarintError::Truncated { needed: 1, have: 0 })
                } else {
                    Err(VarintError::Truncated { needed: width, have: width - 1 })
                }
            );
        }
    }

    #[test]
    fn a_value_over_the_maximum_is_refused_and_leaves_the_buffer_alone() {
        let mut buf = vec![0xAA];
        assert_eq!(
            encode_varint(MAX_VARINT + 1, &mut buf),
            Err(VarintError::TooLarge(MAX_VARINT + 1))
        );
        assert_eq!(encode_varint(u64::MAX, &mut buf), Err(VarintError::TooLarge(u64::MAX)));
        assert_eq!(buf, [0xAA]);
    }

    #[test]
    fn rfc_9000_appendix_a_examples_decode() {
        // The four sample encodings in RFC 9000 appendix A.1.
        assert_eq!(
            decode_varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]).unwrap(),
            (151_288_809_941_952_652, 8)
        );
        assert_eq!(decode_varint(&[0x9d, 0x7f, 0x3e, 0x7d]).unwrap(), (494_878_333, 4));
        assert_eq!(decode_varint(&[0x7b, 0xbd]).unwrap(), (15_293, 2));
        assert_eq!(decode_varint(&[0x25]).unwrap(), (37, 1));
        // A longer-than-needed form of 37 is also valid.
        assert_eq!(decode_varint(&[0x40, 0x25]).unwrap(), (37, 2));
    }

    #[test]
    fn decode_reads_only_its_own_bytes() {
        assert_eq!(decode_varint(&[0x25, 0xFF, 0xFF]).unwrap(), (37, 1));
    }

    #[test]
    fn zigzag_round_trips_and_small_deltas_take_one_byte() {
        let values = [
            0i64,
            -1,
            1,
            -2,
            2,
            -31,
            31,
            -32,
            32,
            -1_000_000,
            1_000_000,
            i64::from(i32::MIN),
            i64::from(i32::MAX),
            -(1i64 << 60),
            1i64 << 60,
        ];
        let mut buf = Vec::new();
        for v in values {
            assert_eq!(zigzag_decode(zigzag_encode(v)), v);
            buf.clear();
            let written = encode_signed_varint(v, &mut buf).unwrap();
            if (-32..=31).contains(&v) {
                assert_eq!(written, 1, "delta {v}");
            }
            assert_eq!(decode_signed_varint(&buf).unwrap(), (v, written));
        }
        assert_eq!(zigzag_encode(-1), 1);
        assert_eq!(zigzag_encode(1), 2);
        assert_eq!(zigzag_encode(i64::MIN), u64::MAX);
    }

    #[test]
    fn a_signed_value_outside_the_range_is_refused() {
        let mut buf = Vec::new();
        for v in [i64::MIN, i64::MAX, (1i64 << 61), -(1i64 << 61) - 1] {
            assert_eq!(
                encode_signed_varint(v, &mut buf),
                Err(VarintError::SignedOutOfRange(v)),
                "{v}"
            );
        }
        assert!(buf.is_empty());
        // The edge that still fits: zigzag = MAX_VARINT.
        assert_eq!(encode_signed_varint((1i64 << 61) - 1, &mut buf).unwrap(), 8);
        assert_eq!(encode_signed_varint(-(1i64 << 61), &mut buf).unwrap(), 8);
    }

    #[test]
    fn a_length_prefixed_slice_round_trips_and_obeys_the_limit() {
        let mut buf = Vec::new();
        encode_len_prefixed(b"hello", &mut buf).unwrap();
        buf.extend_from_slice(b"tail");
        let (slice, used) = decode_len_prefixed(&buf, 16).unwrap();
        assert_eq!((slice, used), (&b"hello"[..], 6));
        assert_eq!(
            decode_len_prefixed(&buf, 4),
            Err(VarintError::LengthOverLimit { len: 5, max: 4 })
        );
        // The prefix says 5 bytes, only 2 follow.
        assert_eq!(
            decode_len_prefixed(&buf[..3], 16),
            Err(VarintError::Truncated { needed: 6, have: 3 })
        );
    }

    #[test]
    fn a_huge_length_prefix_does_not_overflow() {
        let mut buf = Vec::new();
        encode_varint(MAX_VARINT, &mut buf).unwrap();
        assert!(matches!(
            decode_len_prefixed(&buf, usize::MAX),
            Err(VarintError::Truncated { .. } | VarintError::LengthOverLimit { .. })
        ));
    }
}
