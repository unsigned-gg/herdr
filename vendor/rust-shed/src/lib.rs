//! `rust-shed` — Shared Rust utility shed (`facebookexperimental/rust-shed` primitives)
//! and centralized dependency facade for the Cerebral estate.
//!
//! Updating a crate version in `rust-shed/Cargo.toml` updates all downstream crates
//! that consume the dependency through `rust_shed::*`.

#[cfg(feature = "auth0")]
pub mod auth0;
pub mod borrowed;
pub mod cloned;
pub mod lock_ext;
pub mod shared_error;
pub mod time_ext;

#[cfg(feature = "async")]
pub mod async_once_cell;
#[cfg(feature = "async")]
pub mod futures_ext;

// --- Tier 0: Core error & encoding re-exports ---
#[cfg(feature = "core")]
pub use anyhow;
#[cfg(feature = "core")]
pub use base64;
#[cfg(feature = "core")]
pub use eyre;
#[cfg(feature = "core")]
pub use thiserror;

// --- Serialization & data formats ---
#[cfg(feature = "serde")]
pub use serde;
#[cfg(feature = "serde")]
pub use serde_json;
#[cfg(feature = "serde")]
pub use toml;

// --- Time ---
#[cfg(feature = "time")]
pub use chrono;

// --- Synchronization ---
#[cfg(feature = "sync")]
pub use parking_lot;

// --- Async runtime & futures ---
#[cfg(feature = "async")]
pub use async_trait;
#[cfg(feature = "async")]
pub use futures;
#[cfg(feature = "async")]
pub use pin_project;
#[cfg(feature = "async")]
pub use tokio;

// --- HTTP & TLS ---
#[cfg(feature = "http")]
pub use axum;
#[cfg(feature = "http")]
pub use http_body_util;
#[cfg(feature = "http")]
pub use reqwest;
#[cfg(feature = "http")]
pub use tower;

#[cfg(feature = "tls")]
pub use rustls;

// --- Telemetry & metrics ---
#[cfg(feature = "telemetry")]
pub use opentelemetry_proto;
#[cfg(feature = "telemetry")]
pub use prometheus;
#[cfg(feature = "telemetry")]
pub use prost;
#[cfg(feature = "telemetry")]
pub use tracing;
#[cfg(feature = "telemetry")]
pub use tracing_subscriber;

// --- CLI & configuration ---
#[cfg(feature = "cli")]
pub use clap;
#[cfg(feature = "config")]
pub use figment;

// --- Crypto & SQL ---
#[cfg(feature = "crypto")]
pub use jsonwebtoken;
#[cfg(feature = "sql")]
pub use sqlx;

// --- Testing utilities ---
#[cfg(feature = "test-util")]
pub use proptest;
#[cfg(feature = "test-util")]
pub use tempfile;
