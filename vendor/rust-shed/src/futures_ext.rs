// Copyright (c) Meta Platforms, Inc. and affiliates.
// Dual-licensed under MIT OR Apache-2.0 (from facebookexperimental/rust-shed).

//! Future extensions (`FbFutureExt`, `FbTryFutureExt`, `OnCancel`, `ControlledHandle`, `spawn_controlled`)
//! from `facebookexperimental/rust-shed`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::future::{abortable, AbortHandle, FutureExt, Shared, TryFuture, TryFutureExt};
use futures::ready;
use futures::task::{Context, Poll};
use pin_project::{pin_project, pinned_drop};
use tokio::time::Timeout;

use crate::shared_error::anyhow_ext::{AnyhowSharedError, IntoSharedError};

/// Spawn a background task tied to a cloneable [`ControlledHandle`] that aborts the task when all handles drop.
pub fn spawn_controlled<T>(t: T) -> ControlledHandle
where
    T: Future + Send + 'static,
    T::Output: Send + 'static,
{
    let (abortable_future, abort_handle) = abortable(t);
    tokio::task::spawn(abortable_future);
    ControlledHandle::new(abort_handle)
}

/// Cloneable handle that aborts its spawned task when the last handle drops.
#[derive(Clone, Debug)]
pub struct ControlledHandle(#[allow(dead_code)] Arc<ControlledInner>);

impl ControlledHandle {
    fn new(abort_handle: AbortHandle) -> Self {
        Self(Arc::new(ControlledInner(abort_handle)))
    }
}

#[derive(Debug)]
struct ControlledInner(AbortHandle);

impl Drop for ControlledInner {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Combinator that runs `on_cancel` if the inner future is dropped before completing.
#[pin_project(PinnedDrop)]
pub struct OnCancel<Fut, OnCancelFn>
where
    Fut: Future,
    OnCancelFn: FnOnce(),
{
    #[pin]
    inner: Fut,
    on_cancel: Option<OnCancelFn>,
}

impl<Fut, OnCancelFn> OnCancel<Fut, OnCancelFn>
where
    Fut: Future,
    OnCancelFn: FnOnce(),
{
    /// Wrap `inner` with an `on_cancel` callback.
    pub fn new(inner: Fut, on_cancel: OnCancelFn) -> Self {
        Self { inner, on_cancel: Some(on_cancel) }
    }
}

impl<Fut, OnCancelFn> Future for OnCancel<Fut, OnCancelFn>
where
    Fut: Future,
    OnCancelFn: FnOnce(),
{
    type Output = Fut::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let v = ready!(this.inner.poll(cx));
        *this.on_cancel = None;
        Poll::Ready(v)
    }
}

#[pinned_drop]
impl<Fut, OnCancelFn> PinnedDrop for OnCancel<Fut, OnCancelFn>
where
    Fut: Future,
    OnCancelFn: FnOnce(),
{
    fn drop(self: Pin<&mut Self>) {
        let this = self.project();
        if let Some(on_cancel) = this.on_cancel.take() {
            on_cancel();
        }
    }
}

/// Shared fallible future type alias using [`AnyhowSharedError`].
pub type TryShared<Fut> =
    Shared<futures::future::MapErr<Fut, fn(anyhow::Error) -> AnyhowSharedError>>;

/// Future extension methods from `facebookexperimental/rust-shed`.
pub trait FbFutureExt: Future {
    /// Wrap this future in a [`tokio::time::Timeout`].
    fn timeout(self, timeout: Duration) -> Timeout<Self>
    where
        Self: Sized,
    {
        tokio::time::timeout(timeout, self)
    }

    /// Invoke `on_cancel` if this future is dropped before completion.
    fn on_cancel<F: FnOnce()>(self, on_cancel: F) -> OnCancel<Self, F>
    where
        Self: Sized,
    {
        OnCancel::new(self, on_cancel)
    }
}

impl<T: Future + ?Sized> FbFutureExt for T {}

/// Fallible future extension methods from `facebookexperimental/rust-shed`.
pub trait FbTryFutureExt: Future {
    /// Create a cloneable shared handle to a future returning `Result<T, anyhow::Error>`.
    fn try_shared(self) -> TryShared<Self>
    where
        Self: TryFuture<Error = anyhow::Error> + Sized,
        <Self as TryFuture>::Ok: Clone,
    {
        self.map_err(
            IntoSharedError::<AnyhowSharedError>::shared_error
                as fn(anyhow::Error) -> AnyhowSharedError,
        )
        .shared()
    }
}

impl<T: TryFuture + ?Sized> FbTryFutureExt for T {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[tokio::test]
    async fn on_cancel_fires_only_when_dropped_early() {
        let canceled = AtomicBool::new(false);
        let fut = async {}.on_cancel(|| canceled.store(true, Ordering::SeqCst));
        drop(fut);
        assert!(canceled.load(Ordering::SeqCst));

        let completed_cancel = AtomicBool::new(false);
        async {}.on_cancel(|| completed_cancel.store(true, Ordering::SeqCst)).await;
        assert!(!completed_cancel.load(Ordering::SeqCst));
    }
}
