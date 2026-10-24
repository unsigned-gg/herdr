# `rust-shed`

Shared Rust utility shed (`facebookexperimental/rust-shed` primitives) and centralized dependency rollup crate for the Cerebral estate (`vilicus`, `revenant`, `cortex`).

## Purpose

Instead of duplicating third-party dependency versions and feature flags across dozens of member crates, workspace crates depend on `rust-shed` with capability feature flags:

```toml
[dependencies]
rust-shed = { workspace = true, features = ["core", "serde", "async", "http", "telemetry"] }
```

## Feature Tiers

| Feature | Re-exported Crates & Primitives |
|---|---|
| `core` *(default)* | `anyhow`, `thiserror`, `eyre`, `base64`, plus `cloned!`, `borrowed!`, `lock_ext`, `time_ext`, `shared_error` |
| `serde` *(default)* | `serde`, `serde_json`, `toml` |
| `time` *(default)* | `chrono` |
| `sync` | `parking_lot` (+ `LockExt` / `RwLockExt` impls for `parking_lot`) |
| `async` | `tokio`, `futures`, `async_trait`, `pin_project`, plus `async_once_cell` and `futures_ext` |
| `http` | `axum`, `reqwest`, `tower`, `http_body_util` (implies `async`, `serde`) |
| `tls` | `rustls` |
| `telemetry` | `tracing`, `tracing_subscriber`, `prometheus`, `opentelemetry_proto`, `prost` |
| `cli` | `clap` |
| `config` | `figment` (implies `serde`) |
| `crypto` | `jsonwebtoken` (implies `serde`) |
| `sql` | `sqlx` (implies `async`) |
| `test-util` | `tempfile`, `proptest` |
| `full` | Enables all runtime feature tiers above |

## `facebookexperimental/rust-shed` Utilities Included

- [`cloned!`](./src/cloned.rs): Clone variables or struct fields into local bindings before `move` closures or `async move` blocks.
- [`borrowed!`](./src/borrowed.rs): Borrow variables or struct fields into local references before closures or async blocks.
- [`lock_ext`](./src/lock_ext.rs): `LockExt::with` and `RwLockExt::{with_read, with_write}` for `std::sync` and `parking_lot` locks.
- [`time_ext`](./src/time_ext.rs): `DurationExt` and `InstantExt` checked/unchecked conversions.
- [`shared_error`](./src/shared_error.rs): Cloneable `Arc`-backed `SharedError` and `AnyhowSharedError`.
- [`async_once_cell`](./src/async_once_cell.rs): `AsyncOnceCell<T>` lazy async initialization cell.
- [`futures_ext`](./src/futures_ext.rs): `FbFutureExt`, `FbTryFutureExt`, `OnCancel`, `ControlledHandle`, and `spawn_controlled`.
