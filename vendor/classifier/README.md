# vendor/classifier

Vendored System 1 classifier engine and fast reflex gate for the Cerebral estate.

## Architecture

`classifier` is a standalone, line-rate classification crate designed to operate within strict latency budgets (<40ms multi-engine, <0.1ms deterministic fast reflex):

1. **`RefClassifier` (System 1 Fast Reflex)**:
   - Sub-millisecond deterministic safety triage (<0.1ms)
   - Estate gate tiers: **和面 GREEN** (proceed), **赤鬼 RED** (operator sign-off required), **封印 NEVER** (forbidden / anti-priors)
   - Anti-prior contradiction traps (e.g., Lyra decommissioned cluster references, tmux multiplexer references)

2. **`JevClient` (TypeSafe AI)**:
   - Schema-constrained non-autoregressive decision model
   - Eliminates hallucinations by disallowing unconstrained text generation
   - Single forward pass across typed questions (Boolean, Choice, Score)

3. **`ClefClient` (Cloudflare Workers AI)**:
   - Clef 27B: Dense high-precision decision model
   - Clef-flash 9B: Line-rate ultra-low latency model (<40ms)
   - Clef-omni 30B MoE: Direct audio/acoustic feature triage

4. **`UnifiedClassifier`**:
   - Multi-tier classification pipeline uniting Ref, Jev, and Clef
   - Supports automated routing (`auto`), targeted backend selection (`jev`, `clef`, `ref`), and concurrent consensus (`ensemble`)

5. **`ClaimsAttestationEngine`**:
   - Ambient factual claims detection across transcripts and execution streams
   - Cryptographic SHA-256 sealed attestation proofs with empirical verification probes

## Integration

In accordance with estate patterns established by `vendor/rust-shed` and `reverie/vendor/*`, this crate resides in `vendor/classifier` and is consumed across workspace crates including `cortex-adk` and `cortex-cli`.
