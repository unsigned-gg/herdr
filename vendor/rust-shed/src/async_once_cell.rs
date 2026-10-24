// Copyright (c) Meta Platforms, Inc. and affiliates.
// Dual-licensed under MIT OR Apache-2.0 (from facebookexperimental/rust-shed).

//! Async Once Cell (`AsyncOnceCell`) from `facebookexperimental/rust-shed`.

use std::cell::UnsafeCell;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Mutex as AsyncMutex;

/// Cell that is initialized at most once and supports async initialization.
#[derive(Debug)]
pub struct AsyncOnceCell<T> {
    mutex: AsyncMutex<()>,
    is_initialized: AtomicBool,
    value: UnsafeCell<Option<T>>,
}

unsafe impl<T: Sync + Send> Sync for AsyncOnceCell<T> {}
unsafe impl<T: Send> Send for AsyncOnceCell<T> {}

impl<T> Default for AsyncOnceCell<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> AsyncOnceCell<T> {
    /// Construct a new uninitialized `AsyncOnceCell`.
    pub const fn new() -> Self {
        Self {
            mutex: AsyncMutex::const_new(()),
            is_initialized: AtomicBool::new(false),
            value: UnsafeCell::new(None),
        }
    }

    /// Construct a pre-initialized `AsyncOnceCell`.
    pub const fn new_with(value: T) -> Self {
        Self {
            mutex: AsyncMutex::const_new(()),
            is_initialized: AtomicBool::new(true),
            value: UnsafeCell::new(Some(value)),
        }
    }

    /// Returns `true` if initialized.
    pub fn is_initialized(&self) -> bool {
        self.is_initialized.load(Ordering::Acquire)
    }

    /// Returns a reference to the current value without checking initialization.
    ///
    /// # Safety
    /// The cell must already be initialized.
    pub unsafe fn get_unchecked(&self) -> &T {
        unsafe {
            debug_assert!(self.is_initialized());
            let slot = &*self.value.get();
            slot.as_ref().expect("should be initialized")
        }
    }

    /// Returns a reference to the value if initialized.
    pub fn get(&self) -> Option<&T> {
        if self.is_initialized() {
            return unsafe { Some(self.get_unchecked()) };
        }
        None
    }

    /// Set the cell value if uninitialized.
    pub async fn set(&self, value: T) -> Result<(), T> {
        if self.is_initialized() {
            return Err(value);
        }
        let _guard = self.mutex.lock().await;
        if self.is_initialized() {
            return Err(value);
        }
        let slot = self.value.get();
        unsafe {
            debug_assert!((*slot).is_none());
            *slot = Some(value);
        }
        self.is_initialized.store(true, Ordering::Release);
        Ok(())
    }

    /// Get the value or initialize it asynchronously.
    pub async fn get_or_init<F, Fut>(&self, f: F) -> &T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        if self.is_initialized() {
            return unsafe { self.get_unchecked() };
        }
        let _guard = self.mutex.lock().await;
        if self.is_initialized() {
            return unsafe { self.get_unchecked() };
        }
        let value = f().await;
        let slot = self.value.get();
        unsafe {
            debug_assert!((*slot).is_none());
            *slot = Some(value);
        }
        self.is_initialized.store(true, Ordering::Release);
        unsafe { self.get_unchecked() }
    }

    /// Get the value or fallibly initialize it asynchronously.
    pub async fn get_or_try_init<F, Fut, E>(&self, f: F) -> Result<&T, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        if self.is_initialized() {
            return unsafe { Ok(self.get_unchecked()) };
        }
        let _guard = self.mutex.lock().await;
        if self.is_initialized() {
            return unsafe { Ok(self.get_unchecked()) };
        }
        let value = f().await?;
        let slot = self.value.get();
        unsafe {
            debug_assert!((*slot).is_none());
            *slot = Some(value);
        }
        self.is_initialized.store(true, Ordering::Release);
        unsafe { Ok(self.get_unchecked()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn async_once_cell_init_and_set() {
        let cell = AsyncOnceCell::new();
        assert_eq!(cell.get(), None);
        assert_eq!(cell.get_or_init(|| async { 99 }).await, &99);
        assert_eq!(cell.set(100).await, Err(100));
        assert_eq!(cell.get(), Some(&99));
    }
}
