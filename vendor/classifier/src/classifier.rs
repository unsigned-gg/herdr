// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Christian M. Todie

//! Unified Classification Pipeline: Jev (TypeSafe AI) + Clef (Cloudflare Workers AI) + Ref (System 1).
//!
//! Provides single-pass, line-rate classification across estate transcripts, agent actions,
//! and live audio streams:
//! - TypeSafe AI Jev: Schema-constrained non-autoregressive decision model (Boolean, Choice, Score)
//! - Cloudflare Clef: Ultra-low latency line-rate decision models (Clef Flash 9B <40ms, Clef 27B, Clef Omni 30B)
//! - Ref: Deterministic sub-millisecond estate safety triage & anti-prior enforcement (<0.1ms)

use crate::claims_attestation::{ClaimsAttestationEngine, SemanticClaim};
use crate::clef::{ClefClient, ClefModel};
use crate::jev::JevClient;
use crate::models::{
    AnswerValue, DecisionQuestion, DecisionVerdict, GateVerdict, QuestionType, SafetyTier,
};
use crate::systemone::RefClassifier;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// Classifier engine backend selection.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassifierEngine {
    /// Automatic tiering: Ref -> Clef Flash line-rate or Jev schema evaluation
    #[default]
    Auto,
    /// TypeSafe AI Jev decision engine (schema-constrained, no text generation)
    Jev,
    /// Cloudflare Workers AI Clef decision engine (Clef 27B / Flash 9B / Omni 30B)
    Clef,
    /// System 1 fast reflex deterministic safety gate (<0.1ms)
    Ref,
    /// Multi-tier ensemble combining Ref, Jev, and Clef for cross-validated verification
    Ensemble,
}

impl std::str::FromStr for ClassifierEngine {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "jev" | "typesafe" => Ok(Self::Jev),
            "clef" | "cloudflare" => Ok(Self::Clef),
            "ref" | "reflex" | "fast" | "systemone" => Ok(Self::Ref),
            "ensemble" | "all" => Ok(Self::Ensemble),
            other => Err(format!("unknown classifier engine: {other}")),
        }
    }
}

/// Consolidated classification result across all participating engines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedClassificationResult {
    /// Estate doctrine safety tier: 和面 GREEN · 赤鬼 RED · 封印 NEVER
    pub safety_tier: SafetyTier,
    /// Gate verdict from deterministic reflex stage
    pub gate_verdict: GateVerdict,
    /// Name and version of primary classification engine utilized
    pub engine_used: String,
    /// Total wall-clock latency in milliseconds
    pub latency_ms: f64,
    /// Model confidence (0.0 to 1.0)
    pub confidence: f64,
    /// Typed schema answers (key -> value)
    pub answers: HashMap<String, AnswerValue>,
    /// Associated answer probabilities
    pub probabilities: HashMap<String, f64>,
    /// Ambient falsifiable claims detected in input
    pub claims: Vec<SemanticClaim>,
    /// ISO-8601 evaluation timestamp
    pub evaluated_at: String,
}

/// Unified estate classifier uniting TypeSafe Jev, Cloudflare Clef, and Ref (System 1).
pub struct UnifiedClassifier {
    jev: JevClient,
    clef: ClefClient,
    claims_engine: tokio::sync::Mutex<ClaimsAttestationEngine>,
}

impl Default for UnifiedClassifier {
    fn default() -> Self {
        Self::new(JevClient::default(), ClefClient::default())
    }
}

impl UnifiedClassifier {
    pub fn new(jev: JevClient, clef: ClefClient) -> Self {
        Self {
            jev,
            clef,
            claims_engine: tokio::sync::Mutex::new(ClaimsAttestationEngine::new()),
        }
    }

    /// Generate standard estate triage questions for schema evaluation.
    pub fn default_triage_questions() -> Vec<DecisionQuestion> {
        vec![
            DecisionQuestion {
                key: "is_destructive".to_string(),
                prompt: "Does this action delete, drop, wipe, or mutate critical state?"
                    .to_string(),
                question_type: QuestionType::Boolean,
            },
            DecisionQuestion {
                key: "is_emergency".to_string(),
                prompt: "Is this an urgent halt or immediate abort request?".to_string(),
                question_type: QuestionType::Boolean,
            },
            DecisionQuestion {
                key: "category".to_string(),
                prompt: "Categorize the primary intent".to_string(),
                question_type: QuestionType::Choice {
                    options: vec![
                        "safe_read".to_string(),
                        "infra_mutation".to_string(),
                        "secret_access".to_string(),
                        "deployment".to_string(),
                        "emergency_halt".to_string(),
                    ],
                },
            },
            DecisionQuestion {
                key: "urgency_score".to_string(),
                prompt: "Rate the urgency of the requested action from 0.0 to 1.0".to_string(),
                question_type: QuestionType::Score { min: 0.0, max: 1.0 },
            },
        ]
    }

    /// Classify arbitrary textual state, command input, or transcript content.
    pub async fn classify_text(
        &self,
        text: &str,
        engine: ClassifierEngine,
        custom_questions: Option<&[DecisionQuestion]>,
    ) -> anyhow::Result<UnifiedClassificationResult> {
        let start = Instant::now();

        // 1. Stage 1: Deterministic Ref Triage (<0.1ms)
        let (gate_verdict, _) = RefClassifier::evaluate(text);
        let ref_tier = gate_verdict.tier();

        // Detect ambient falsifiable claims
        let detected_claims = {
            let mut engine = self.claims_engine.lock().await;
            engine.extract_claims(text)
        };

        let default_questions = Self::default_triage_questions();
        let questions = custom_questions.unwrap_or(&default_questions);

        // If Ref tier is strictly NEVER or engine is Ref only, return immediately
        if engine == ClassifierEngine::Ref
            || (ref_tier == SafetyTier::Never && engine == ClassifierEngine::Auto)
        {
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            let mut answers = HashMap::new();
            let mut probabilities = HashMap::new();

            answers.insert(
                "is_destructive".to_string(),
                AnswerValue::Boolean(ref_tier == SafetyTier::Never),
            );
            probabilities.insert(
                "is_destructive".to_string(),
                if ref_tier == SafetyTier::Never {
                    0.999
                } else {
                    0.001
                },
            );

            return Ok(UnifiedClassificationResult {
                safety_tier: ref_tier,
                gate_verdict,
                engine_used: "RefClassifier (System 1)".to_string(),
                latency_ms: elapsed_ms,
                confidence: 0.99,
                answers,
                probabilities,
                claims: detected_claims,
                evaluated_at: Utc::now().to_rfc3339(),
            });
        }

        // 2. Stage 2: Dispatch to selected model engine
        let (verdict, engine_name) = match engine {
            ClassifierEngine::Ref => unreachable!(),
            ClassifierEngine::Jev => {
                let v = self.jev.evaluate(text, questions).await?;
                (v, "TypeSafe AI Jev (jev-v1)")
            }
            ClassifierEngine::Clef => {
                let v = self
                    .clef
                    .evaluate_text(text, questions, Some(ClefModel::ClefFlash9b))
                    .await?;
                (v, "Cloudflare Workers AI (@cf/cloudflare/clef-flash-9b)")
            }
            ClassifierEngine::Auto => {
                // Auto routes based on input characteristics:
                // If text length < 256 or emergency keywords present, use Clef Flash for line-rate (<40ms)
                // Otherwise use Jev for schema evaluation
                if text.len() < 256 || text.to_lowercase().contains("abort") {
                    let v = self
                        .clef
                        .evaluate_text(text, questions, Some(ClefModel::ClefFlash9b))
                        .await?;
                    (v, "Auto -> Clef Flash 9B (<40ms)")
                } else {
                    let v = self.jev.evaluate(text, questions).await?;
                    (v, "Auto -> TypeSafe Jev")
                }
            }
            ClassifierEngine::Ensemble => {
                // Cross-evaluate both Jev and Clef concurrently
                let (jev_res, clef_res) = tokio::join!(
                    self.jev.evaluate(text, questions),
                    self.clef
                        .evaluate_text(text, questions, Some(ClefModel::ClefFlash9b))
                );

                let jev_verdict = jev_res.unwrap_or_else(|_| DecisionVerdict {
                    model: "jev-fallback".to_string(),
                    latency_ms: 0.0,
                    answers: HashMap::new(),
                    probabilities: HashMap::new(),
                    confidence: 0.5,
                    safety_tier: SafetyTier::Green,
                    raw_state_length: text.len(),
                });

                let clef_verdict = clef_res.unwrap_or_else(|_| DecisionVerdict {
                    model: "clef-fallback".to_string(),
                    latency_ms: 0.0,
                    answers: HashMap::new(),
                    probabilities: HashMap::new(),
                    confidence: 0.5,
                    safety_tier: SafetyTier::Green,
                    raw_state_length: text.len(),
                });

                // Merge answers and calibrate confidence
                let mut combined_answers = jev_verdict.answers;
                for (k, v) in clef_verdict.answers {
                    combined_answers.entry(k).or_insert(v);
                }

                let mut combined_probs = jev_verdict.probabilities;
                for (k, p) in clef_verdict.probabilities {
                    combined_probs.entry(k).or_insert(p);
                }

                let higher_conf = jev_verdict.confidence.max(clef_verdict.confidence);
                let joint_tier = match (
                    ref_tier,
                    jev_verdict.safety_tier,
                    clef_verdict.safety_tier,
                ) {
                    (SafetyTier::Never, _, _)
                    | (_, SafetyTier::Never, _)
                    | (_, _, SafetyTier::Never) => SafetyTier::Never,
                    (SafetyTier::Red, _, _) | (_, SafetyTier::Red, _) | (_, _, SafetyTier::Red) => {
                        SafetyTier::Red
                    }
                    _ => SafetyTier::Green,
                };

                let ensemble_verdict = DecisionVerdict {
                    model: "Ensemble(Jev + Clef + Ref)".to_string(),
                    latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                    answers: combined_answers,
                    probabilities: combined_probs,
                    confidence: higher_conf,
                    safety_tier: joint_tier,
                    raw_state_length: text.len(),
                };

                (
                    ensemble_verdict,
                    "Ensemble (TypeSafe Jev + Cloudflare Clef + Ref)",
                )
            }
        };

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        // Composite safety tier respects strictest gate
        let final_tier = match (ref_tier, verdict.safety_tier) {
            (SafetyTier::Never, _) | (_, SafetyTier::Never) => SafetyTier::Never,
            (SafetyTier::Red, _) | (_, SafetyTier::Red) => SafetyTier::Red,
            _ => SafetyTier::Green,
        };

        Ok(UnifiedClassificationResult {
            safety_tier: final_tier,
            gate_verdict,
            engine_used: engine_name.to_string(),
            latency_ms: elapsed_ms,
            confidence: verdict.confidence,
            answers: verdict.answers,
            probabilities: verdict.probabilities,
            claims: detected_claims,
            evaluated_at: Utc::now().to_rfc3339(),
        })
    }

    /// Classify audio features directly via Clef-omni (30B MoE).
    pub async fn classify_audio(
        &self,
        duration_ms: u64,
        pitch_f0_mean: f64,
        energy_rms: f64,
    ) -> anyhow::Result<UnifiedClassificationResult> {
        let start = Instant::now();

        let verdict = self
            .clef
            .evaluate_audio_features(duration_ms, pitch_f0_mean, energy_rms)
            .await?;

        let is_urgent = verdict
            .answers
            .get("is_urgent")
            .and_then(|v| match v {
                AnswerValue::Boolean(b) => Some(*b),
                _ => None,
            })
            .unwrap_or(false);

        let gate_verdict = if is_urgent {
            GateVerdict::GateRed {
                intent: "HIGH_AROUSAL_URGENT_AUDIO".to_string(),
                requirement:
                    "Acoustic arousal threshold exceeded; operator acknowledgment required"
                        .to_string(),
                confidence: verdict.confidence,
            }
        } else {
            GateVerdict::Allow {
                intent: "NORMAL_PROSODY_AUDIO".to_string(),
                confidence: verdict.confidence,
            }
        };

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        Ok(UnifiedClassificationResult {
            safety_tier: verdict.safety_tier,
            gate_verdict,
            engine_used: "Cloudflare Clef-omni 30B MoE (Direct Audio)".to_string(),
            latency_ms: elapsed_ms,
            confidence: verdict.confidence,
            answers: verdict.answers,
            probabilities: verdict.probabilities,
            claims: Vec::new(),
            evaluated_at: Utc::now().to_rfc3339(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unified_classifier_ref_fast_path() {
        let classifier = UnifiedClassifier::default();
        let res = classifier
            .classify_text("rm -rf /data", ClassifierEngine::Ref, None)
            .await
            .unwrap();

        assert_eq!(res.safety_tier, SafetyTier::Never);
        assert!(res.latency_ms < 5.0);
    }

    #[tokio::test]
    async fn test_unified_classifier_jev() {
        let classifier = UnifiedClassifier::default();
        let res = classifier
            .classify_text("Halt all tasks immediately", ClassifierEngine::Jev, None)
            .await
            .unwrap();

        assert_eq!(
            res.answers.get("is_emergency"),
            Some(&AnswerValue::Boolean(true))
        );
        assert!(res.engine_used.contains("Jev"));
    }

    #[tokio::test]
    async fn test_unified_classifier_clef() {
        let classifier = UnifiedClassifier::default();
        let res = classifier
            .classify_text("read configuration file", ClassifierEngine::Clef, None)
            .await
            .unwrap();

        assert_eq!(res.safety_tier, SafetyTier::Green);
        assert!(res.engine_used.to_lowercase().contains("clef"));
    }

    #[tokio::test]
    async fn test_unified_classifier_ensemble() {
        let classifier = UnifiedClassifier::default();
        let res = classifier
            .classify_text(
                "Cygnus is the sole cluster. Verify 15 tests passed.",
                ClassifierEngine::Ensemble,
                None,
            )
            .await
            .unwrap();

        assert_eq!(res.safety_tier, SafetyTier::Green);
        assert!(!res.claims.is_empty());
        assert!(res.engine_used.contains("Ensemble"));
    }

    #[tokio::test]
    async fn test_unified_classifier_audio() {
        let classifier = UnifiedClassifier::default();
        let res = classifier.classify_audio(900, 275.0, 0.82).await.unwrap();

        assert_eq!(res.safety_tier, SafetyTier::Red);
        assert_eq!(
            res.answers.get("is_urgent"),
            Some(&AnswerValue::Boolean(true))
        );
    }
}
