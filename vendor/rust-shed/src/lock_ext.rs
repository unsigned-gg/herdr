// Copyright (c) Meta Platforms, Inc. and affiliates.
// Dual-licensed under MIT OR Apache-2.0 (from facebookexperimental/rust-shed).

//! Extensions for `std::sync::{Mutex, RwLock}` and `parking_lot::{Mutex, RwLock}`.

use std::sync::{Mutex, RwLock};

#[cfg(feature = "sync")]
use parking_lot::{Mutex as ParkingLotMutex, RwLock as ParkingLotRwLock};

/// Scoped access helper for `Mutex`.
pub trait LockExt {
    /// Value protected by the mutex.
    type Value;

    /// Acquire the lock and pass `&mut Self::Value` to `scope`.
    fn with<Scope, Out>(&self, scope: Scope) -> Out
    where
        Scope: FnOnce(&mut Self::Value) -> Out;
}

impl<V> LockExt for Mutex<V> {
    type Value = V;

    fn with<Scope, Out>(&self, scope: Scope) -> Out
    where
        Scope: FnOnce(&mut Self::Value) -> Out,
    {
        let mut value = self.lock().expect("lock poisoned");
        scope(&mut *value)
    }
}

#[cfg(feature = "sync")]
impl<V> LockExt for ParkingLotMutex<V> {
    type Value = V;

    fn with<Scope, Out>(&self, scope: Scope) -> Out
    where
        Scope: FnOnce(&mut Self::Value) -> Out,
    {
        let mut value = self.lock();
        scope(&mut *value)
    }
}

/// Scoped access helper for `RwLock`.
pub trait RwLockExt {
    /// Value protected by the read-write lock.
    type Value;

    /// Acquire the read lock and pass `&Self::Value` to `scope`.
    fn with_read<Scope, Out>(&self, scope: Scope) -> Out
    where
        Scope: FnOnce(&Self::Value) -> Out;

    /// Acquire the write lock and pass `&mut Self::Value` to `scope`.
    fn with_write<Scope, Out>(&self, scope: Scope) -> Out
    where
        Scope: FnOnce(&mut Self::Value) -> Out;
}

impl<V> RwLockExt for RwLock<V> {
    type Value = V;

    fn with_read<Scope, Out>(&self, scope: Scope) -> Out
    where
        Scope: FnOnce(&Self::Value) -> Out,
    {
        let value = self.read().expect("lock poisoned");
        scope(&*value)
    }

    fn with_write<Scope, Out>(&self, scope: Scope) -> Out
    where
        Scope: FnOnce(&mut Self::Value) -> Out,
    {
        let mut value = self.write().expect("lock poisoned");
        scope(&mut *value)
    }
}

#[cfg(feature = "sync")]
impl<V> RwLockExt for ParkingLotRwLock<V> {
    type Value = V;

    fn with_read<Scope, Out>(&self, scope: Scope) -> Out
    where
        Scope: FnOnce(&Self::Value) -> Out,
    {
        let value = self.read();
        scope(&*value)
    }

    fn with_write<Scope, Out>(&self, scope: Scope) -> Out
    where
        Scope: FnOnce(&mut Self::Value) -> Out,
    {
        let mut value = self.write();
        scope(&mut *value)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, RwLock};

    use super::{LockExt, RwLockExt};

    #[test]
    fn mutex_and_rwlock_with() {
        let m = Arc::new(Mutex::new(Vec::new()));
        m.with(|v| v.push(7));
        assert_eq!(m.with(|v| v.pop()), Some(7));

        let rw = Arc::new(RwLock::new(Vec::new()));
        rw.with_write(|v| v.push("ok"));
        assert_eq!(rw.with_read(|v| v.len()), 1);
    }
}
