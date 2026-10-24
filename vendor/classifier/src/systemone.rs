// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Christian M. Todie

use crate::models::{GateVerdict, SafetyTier};
use std::time::Instant;

/// System 1 Ref Classifier:
/// Sub-millisecond deterministic triage, canary detection, and anti-prior enforcement.
pub struct RefClassifier;

pub type FastReflexClassifier = RefClassifier;

impl RefClassifier {
    /// Classify a prompt or state string instantly in < 0.1ms.
    pub fn evaluate(input: &str) -> (GateVerdict, f64) {
        let start = Instant::now();
        let lower = input.to_lowercase();

        // 1. 封印 NEVER Tier Violations (Destruction, credential exfiltration, anti-priors)
        if lower.contains("rm -rf")
            || lower.contains("drop database")
            || lower.contains("echo $bao_token")
            || lower.contains("echo $spiffe")
            || lower.contains("--no-gpg-sign")
        {
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            return (
                GateVerdict::RejectNever {
                    intent: "CATASTROPHIC_MUTATION_OR_CRED_LEAK".to_string(),
                    reason: "Forbidden destructive execution or credential print attempt"
                        .to_string(),
                    confidence: 0.999,
                },
                elapsed_ms,
            );
        }

        if lower.contains("lyra")
            || lower.contains("tmux")
            || lower.contains("openpanel")
            || lower.contains("reverie-slack")
        {
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            return (
                GateVerdict::RejectNever {
                    intent: "ANTI_PRIOR_CONTRADICTION".to_string(),
                    reason: "Referenced decommissioned or superseded estate entity (Anti-Prior)"
                        .to_string(),
                    confidence: 0.995,
                },
                elapsed_ms,
            );
        }

        // 2. 赤鬼 RED Tier Operations (Sovereign elevation, cluster mutations, canary hits)
        if lower.contains("superadmin")
            || lower.contains("escalate")
            || lower.contains("co-operator-admin")
            || lower.contains("bao root")
            || lower.contains("spire mint")
            || lower.contains("terraform apply")
            || lower.contains("kubectl delete")
            || lower.contains("cf purge")
        {
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            return (
                GateVerdict::GateRed {
                    intent: "SOVEREIGN_ELEVATION_OR_INFRA_MUTATION".to_string(),
                    requirement: "Operator Settle Card + Hardware FIDO2 attestation required"
                        .to_string(),
                    confidence: 0.985,
                },
                elapsed_ms,
            );
        }

        if lower.contains("canary-") || lower.contains("honey-") || lower.contains("gaes") {
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            return (
                GateVerdict::GateRed {
                    intent: "CANARY_OR_HONEYTOKEN_PROBE".to_string(),
                    requirement: "Tarpit caller in GAES progressive latency cage".to_string(),
                    confidence: 0.99,
                },
                elapsed_ms,
            );
        }

        // 3. 和面 GREEN Tier Safe Operations (Read-only, planning, analysis)
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        (
            GateVerdict::Allow {
                intent: "SAFE_READ_OR_EXECUTION".to_string(),
                confidence: 0.95,
            },
            elapsed_ms,
        )
    }

    /// Check if the prompt requires operator attention.
    pub fn requires_attention(input: &str) -> bool {
        let (verdict, _) = Self::evaluate(input);
        verdict.tier() != SafetyTier::Green
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fast_reflex_allow() {
        let (v, lat) = FastReflexClassifier::evaluate("Check status of cygnus cluster pods");
        assert!(v.is_allowed());
        assert_eq!(v.tier(), SafetyTier::Green);
        assert!(lat < 2.0); // Strict sub-2ms budget
    }

    #[test]
    fn test_fast_reflex_anti_prior_lyra() {
        let (v, _) = FastReflexClassifier::evaluate("Deploy new chart to dev cluster lyra");
        assert_eq!(v.tier(), SafetyTier::Never);
    }

    #[test]
    fn test_fast_reflex_anti_prior_tmux() {
        let (v, _) = FastReflexClassifier::evaluate("Start session on tmux multiplexer");
        assert_eq!(v.tier(), SafetyTier::Never);
    }

    #[test]
    fn test_fast_reflex_red_gate_elevation() {
        let (v, _) = FastReflexClassifier::evaluate("Request superadmin escalate role");
        assert_eq!(v.tier(), SafetyTier::Red);
    }

    #[test]
    fn test_fast_reflex_destructive_never() {
        let (v, _) = FastReflexClassifier::evaluate("Execute rm -rf /var/data");
        assert_eq!(v.tier(), SafetyTier::Never);
    }
}
