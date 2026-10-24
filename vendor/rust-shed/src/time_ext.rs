// Copyright (c) Meta Platforms, Inc. and affiliates.
// Dual-licensed under MIT OR Apache-2.0 (from facebookexperimental/rust-shed).

//! Extensions for `std::time::{Duration, Instant}`.

use std::fmt;
use std::time::{Duration, Instant};

/// Error returned when a duration conversion overflows `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverflowError;

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("value too large for u64")
    }
}

impl std::error::Error for OverflowError {}

/// Extension trait for [`Duration`].
pub trait DurationExt {
    /// Whole milliseconds as `u64`, returning an error on overflow.
    fn as_millis_u64(&self) -> Result<u64, OverflowError>;

    /// Whole milliseconds as `u64` without overflow check.
    fn as_millis_unchecked(&self) -> u64;

    /// Whole microseconds as `u64`, returning an error on overflow.
    fn as_micros_u64(&self) -> Result<u64, OverflowError>;

    /// Whole microseconds as `u64` without overflow check.
    fn as_micros_unchecked(&self) -> u64;

    /// Whole nanoseconds as `u64`, returning an error on overflow.
    fn as_nanos_u64(&self) -> Result<u64, OverflowError>;

    /// Whole nanoseconds as `u64` without overflow check.
    fn as_nanos_unchecked(&self) -> u64;

    /// Zero-length duration.
    fn zero() -> Self;

    /// Whether the duration is zero.
    fn is_zero_ext(&self) -> bool;
}

impl DurationExt for Duration {
    fn as_millis_u64(&self) -> Result<u64, OverflowError> {
        self.as_millis().try_into().map_err(|_| OverflowError)
    }

    fn as_millis_unchecked(&self) -> u64 {
        self.as_secs() * 1_000 + u64::from(self.subsec_millis())
    }

    fn as_micros_u64(&self) -> Result<u64, OverflowError> {
        self.as_micros().try_into().map_err(|_| OverflowError)
    }

    fn as_micros_unchecked(&self) -> u64 {
        self.as_secs() * 1_000_000 + u64::from(self.subsec_micros())
    }

    fn as_nanos_u64(&self) -> Result<u64, OverflowError> {
        self.as_nanos().try_into().map_err(|_| OverflowError)
    }

    fn as_nanos_unchecked(&self) -> u64 {
        self.as_secs() * 1_000_000_000 + u64::from(self.subsec_nanos())
    }

    fn zero() -> Self {
        Duration::from_secs(0)
    }

    fn is_zero_ext(&self) -> bool {
        *self == Self::zero()
    }
}

/// Extension trait for [`Instant`].
pub trait InstantExt {
    /// Duration elapsed from `self` until `later`.
    fn duration_until(&self, later: Self) -> Duration;
}

impl InstantExt for Instant {
    fn duration_until(&self, later: Self) -> Duration {
        later.duration_since(*self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_ext_checks() {
        let d = Duration::from_millis(250);
        assert_eq!(d.as_millis_u64(), Ok(250));
        assert_eq!(d.as_micros_u64(), Ok(250_000));
        assert!(Duration::from_secs(u64::MAX).as_nanos_u64().is_err());
        assert!(Duration::zero().is_zero_ext());
    }
}
