// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Christian M. Todie

//! classifier — Vendored System 1 fast reflex and multi-engine decision pipeline.
//!
//! Exposes sub-40ms decision, classification, and empirical attestation engines:
//! - `RefClassifier`: Sub-millisecond deterministic safety triage and anti-prior enforcement (<0.1ms)
//! - `JevClient`: TypeSafe AI schema-constrained decision engine (no text generation)
//! - `ClefClient`: Cloudflare Workers AI decision models (Clef 27B, Clef-flash 9B, Clef-omni 30B MoE)
//! - `UnifiedClassifier`: Multi-tier pipeline combining Ref, Jev, and Clef with ambient claims extraction
//! - `ClaimsAttestationEngine`: Falsifiable factual assertions extraction and cryptographic SHA-256 attestation

pub mod claims_attestation;
pub mod classifier;
pub mod clef;
pub mod jev;
pub mod models;
pub mod systemone;

pub use claims_attestation::{
    AttestationProof, AttestationStatus, ClaimCategory, ClaimsAttestationEngine,
    ClaimsBenchmarkReport, SemanticClaim,
};
pub use classifier::{ClassifierEngine, UnifiedClassificationResult, UnifiedClassifier};
pub use clef::{ClefClient, ClefModel};
pub use jev::JevClient;
pub use models::{
    AnswerValue, DecisionQuestion, DecisionVerdict, GateVerdict, QuestionType, SafetyTier,
};
pub use systemone::{FastReflexClassifier, RefClassifier};
