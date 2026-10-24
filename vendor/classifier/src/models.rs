// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Christian M. Todie

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cognitive Tier according to estate doctrine:
/// 和面 GREEN (proceed) · 赤鬼 RED (operator sign-off required) · 封印 NEVER (forbidden).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyTier {
    #[serde(rename = "和面 GREEN")]
    Green,
    #[serde(rename = "赤鬼 RED")]
    Red,
    #[serde(rename = "封印 NEVER")]
    Never,
}

impl std::fmt::Display for SafetyTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyTier::Green => write!(f, "和面 GREEN"),
            SafetyTier::Red => write!(f, "赤鬼 RED"),
            SafetyTier::Never => write!(f, "封印 NEVER"),
        }
    }
}

/// Instant gate verdict evaluated by System 1 models.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GateVerdict {
    Allow {
        intent: String,
        confidence: f64,
    },
    GateRed {
        intent: String,
        requirement: String,
        confidence: f64,
    },
    RejectNever {
        intent: String,
        reason: String,
        confidence: f64,
    },
}

impl GateVerdict {
    pub fn tier(&self) -> SafetyTier {
        match self {
            GateVerdict::Allow { .. } => SafetyTier::Green,
            GateVerdict::GateRed { .. } => SafetyTier::Red,
            GateVerdict::RejectNever { .. } => SafetyTier::Never,
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self, GateVerdict::Allow { .. })
    }
}

/// Schema-defined question types for decision models (Jev / Clef).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum QuestionType {
    Boolean,
    Choice { options: Vec<String> },
    Score { min: f64, max: f64 },
}

/// A structured question submitted to a System 1 decision engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionQuestion {
    pub key: String,
    pub prompt: String,
    pub question_type: QuestionType,
}

/// Answer values returned by System 1 decision engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AnswerValue {
    Boolean(bool),
    Choice(String),
    Score(f64),
}

/// Calibrated decision result from a System 1 model pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionVerdict {
    pub model: String,
    pub latency_ms: f64,
    pub answers: HashMap<String, AnswerValue>,
    pub probabilities: HashMap<String, f64>,
    pub confidence: f64,
    pub safety_tier: SafetyTier,
    pub raw_state_length: usize,
}
