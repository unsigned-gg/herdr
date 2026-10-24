// Copyright (c) Meta Platforms, Inc. and affiliates.
// Dual-licensed under MIT OR Apache-2.0 (from facebookexperimental/rust-shed).

//! Cloneable `Arc`-backed error wrappers (`SharedError`).

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

/// Cloneable wrapper around a typed `std::error::Error`.
#[derive(Debug)]
pub struct SharedError<T: StdError + 'static> {
    error: Arc<T>,
}

impl<T: StdError + 'static> Clone for SharedError<T> {
    fn clone(&self) -> Self {
        Self { error: Arc::clone(&self.error) }
    }
}

impl<T: StdError + 'static> From<T> for SharedError<T> {
    fn from(error: T) -> Self {
        Self { error: Arc::new(error) }
    }
}

impl<T: StdError + 'static> From<Arc<T>> for SharedError<T> {
    fn from(error: Arc<T>) -> Self {
        Self { error }
    }
}

impl<T: StdError + 'static> fmt::Display for SharedError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.error, f)
    }
}

impl<T: StdError + 'static> StdError for SharedError<T> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.error.source()
    }
}

impl<T: StdError + 'static> SharedError<T> {
    /// Return a reference to the inner error.
    pub fn inner(&self) -> &T {
        &self.error
    }
}

/// Cloneable `Arc<anyhow::Error>` wrapper (enabled with `core` feature).
#[cfg(feature = "core")]
pub mod anyhow_ext {
    use std::fmt;
    use std::sync::Arc;

    use anyhow::Error;

    /// Cloneable `anyhow::Error` wrapper.
    #[derive(Debug, Clone)]
    pub struct AnyhowSharedError {
        error: Arc<Error>,
    }

    impl AnyhowSharedError {
        /// Reference the inner `anyhow::Error`.
        pub fn inner(&self) -> &Error {
            &self.error
        }

        /// Wrap an existing `Arc<anyhow::Error>`.
        pub fn new_arced(error: Arc<Error>) -> Self {
            Self { error }
        }
    }

    impl fmt::Display for AnyhowSharedError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(&*self.error, f)
        }
    }

    impl std::error::Error for AnyhowSharedError {}

    impl From<Arc<Error>> for AnyhowSharedError {
        fn from(error: Arc<Error>) -> Self {
            Self { error }
        }
    }

    /// Convert an error or `Result` into [`AnyhowSharedError`].
    pub trait IntoSharedError<Ret> {
        /// Convert into a cloneable shared error.
        fn shared_error(self) -> Ret;
    }

    impl<E: Into<Error>> IntoSharedError<AnyhowSharedError> for E {
        fn shared_error(self) -> AnyhowSharedError {
            AnyhowSharedError { error: Arc::new(self.into()) }
        }
    }

    impl<T, E: Into<Error>> IntoSharedError<Result<T, AnyhowSharedError>> for Result<T, E> {
        fn shared_error(self) -> Result<T, AnyhowSharedError> {
            self.map_err(IntoSharedError::shared_error)
        }
    }
}
