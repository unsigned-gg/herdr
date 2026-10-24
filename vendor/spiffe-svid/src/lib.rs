//! JWT-SVID verification against the estate SPIFFE trust domain
//! (`unsigned.gg`) — spec `docs/spec/mesh-edge-spiffe.md`.
//!
//! One verifier, shared by every consumer the spec names (the EdgeBridge
//! brain here; blackwall-serve and coral later — they depend on this crate,
//! nothing is copied). The JWKS arrives through a [`JwksSource`] trait: the
//! production source (SPIRE OIDC discovery, D5) is an HTTP fetch wired in a
//! later step; tests inject keys directly.
//!
//! Everything rejected maps to a distinct [`SvidError`] — a caller can tell
//! "replay from another relying party" (WrongAudience) from "wrong trust
//! domain" without parsing message text.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::Algorithm;
use spiffe::{JwtBundle, JwtBundleSet, JwtSvid, JwtSvidError, TrustDomain};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

/// Maximum RFC 8693 nested `act` delegation chain depth (`draft-klrc-aiagent-auth-03`).
pub const MAX_DELEGATION_DEPTH: usize = 8;

/// The verified identity of an edge caller: the host extracted from the
/// verified `sub`, plus the SPIFFE ID and expiry for the stream deadline.
#[derive(Debug, Clone)]
pub struct VerifiedEdgeIdentity {
    pub host: String,
    pub spiffe_id: String,
    /// Seconds since the epoch at which this SVID expires.
    pub exp_unix: u64,
}

/// RFC 8693 Section 4.1 `act` (Actor) claim representing nested agent delegation chains.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ActorClaim {
    /// Subject identifier of the acting party (e.g. `spiffe://unsigned.gg/elf/research/oracle`).
    pub sub: String,
    /// Optional OAuth 2.0 `client_id` of the acting party.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Optional nested prior actor in the delegation chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActorClaim>>,
}

impl ActorClaim {
    /// Validate that the `act` claim chain has non-empty subjects and does not exceed [`MAX_DELEGATION_DEPTH`].
    pub fn validate(&self, depth: usize) -> Result<(), SvidError> {
        if depth > MAX_DELEGATION_DEPTH {
            return Err(SvidError::DelegationDepthExceeded);
        }
        let sub = self.sub.trim();
        if sub.is_empty()
            || sub
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(SvidError::InvalidDelegationClaim);
        }
        if let Some(ref client_id) = self.client_id {
            if client_id.trim().is_empty() {
                return Err(SvidError::InvalidDelegationClaim);
            }
        }
        if let Some(ref inner) = self.act {
            inner.validate(depth + 1)?;
        }
        Ok(())
    }

    /// Return the ordered delegation chain subjects (`[current_actor, ..., root_delegator]`).
    pub fn delegation_chain(&self) -> Vec<String> {
        let mut chain = Vec::new();
        let mut cur = Some(self);
        while let Some(node) = cur {
            chain.push(node.sub.clone());
            cur = node.act.as_deref();
        }
        chain
    }
}

/// Parsed WIMSE / SPIFFE workload identity kind (`draft-klrc-aiagent-auth-03`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WimseIdentityKind {
    /// Host edge daemon (`spiffe://<td >/host/<host>/cortex-edge`).
    HostEdge { host: String },
    /// Autonomous agent session (`spiffe://<td >/agent/<team>/<agent_id>`).
    Agent { team: String, agent_id: String },
    /// Conclave Elf bot (`spiffe://<td >/elf/<mesh>/<elf_id>`).
    ConclaveElf { mesh: String, elf_id: String },
}

/// Verified WIMSE JWT-SVID or RFC 8693 exchanged token with optional `act` delegation chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWimseIdentity {
    pub kind: WimseIdentityKind,
    pub spiffe_id: String,
    pub exp_unix: u64,
    pub act: Option<ActorClaim>,
    pub scope: Option<String>,
}

impl VerifiedWimseIdentity {
    /// Return the full ordered delegation lineage (`[spiffe_id, act.sub, act.act.sub, ...]`).
    pub fn delegation_chain(&self) -> Vec<String> {
        let mut out = vec![self.spiffe_id.clone()];
        if let Some(ref act) = self.act {
            out.extend(act.delegation_chain());
        }
        out
    }
}

/// Path validation policy for neutral SPIFFE ID verification (`CER-2603`).
///
/// Unlike [`SvidVerifier::verify`] (which requires `host/<host>/cortex-edge`) or
/// [`SvidVerifier::verify_wimse`] (which requires `host/...`, `agent/...`, or `elf/...`),
/// [`PathPolicy`] lets callers such as `soma` (`reflexd`), `blackwall-serve`, or `coral`
/// validate arbitrary SPIFFE path shapes such as `cluster/cygnus/ns/<ns>/sa/<sa>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPolicy {
    /// Any non-empty SPIFFE path where every `/`-separated segment is a safe slug (`[a-z0-9_-]{1,63}`).
    AnyNonEmpty,
    /// Requires an exact number of safe slug segments.
    ExactSegments { count: usize },
    /// Requires the path to start with the given literal prefix segments, followed by zero or more safe slug segments.
    PrefixSegments(Vec<String>),
    /// `/`-separated pattern where `*` matches any single valid slug segment (`[a-z0-9_-]{1,63}`)
    /// and any other segment must match literally (e.g. `"cluster/cygnus/ns/*/sa/*"`).
    Pattern(String),
}

impl PathPolicy {
    /// Validate `path` (the portion of `spiffe://<trust_domain>/<path>` after `<trust_domain>/`)
    /// against this policy and return the parsed `/`-separated segments.
    pub fn validate_path(&self, path: &str) -> Result<Vec<String>, SvidError> {
        if path.is_empty() {
            return Err(SvidError::WrongPath);
        }
        let segs: Vec<&str> = path.split('/').collect();
        if segs.is_empty() || !segs.iter().all(|s| valid_agent_segment(s)) {
            return Err(SvidError::WrongPath);
        }
        match self {
            Self::AnyNonEmpty => {}
            Self::ExactSegments { count } => {
                if segs.len() != *count {
                    return Err(SvidError::WrongPath);
                }
            }
            Self::PrefixSegments(prefix) => {
                if prefix.is_empty() || segs.len() < prefix.len() {
                    return Err(SvidError::WrongPath);
                }
                for (actual, expected) in segs.iter().zip(prefix.iter()) {
                    if *actual != expected.as_str() {
                        return Err(SvidError::WrongPath);
                    }
                }
            }
            Self::Pattern(pattern) => {
                if pattern.is_empty() {
                    return Err(SvidError::WrongPath);
                }
                let pat_segs: Vec<&str> = pattern.split('/').collect();
                if pat_segs.len() != segs.len() {
                    return Err(SvidError::WrongPath);
                }
                for (actual, expected) in segs.iter().zip(pat_segs.iter()) {
                    if *expected != "*" && *actual != *expected {
                        return Err(SvidError::WrongPath);
                    }
                }
            }
        }
        Ok(segs.into_iter().map(str::to_string).collect())
    }
}

/// Verified neutral SPIFFE JWT-SVID identity (`CER-2603`).
///
/// Returned by [`SvidVerifier::verify_with_policy`] and [`SvidVerifier::verify_cached`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSpiffeIdentity {
    /// Full `sub` claim (`spiffe://<trust_domain>/<path>`).
    pub spiffe_id: String,
    /// Verified trust domain (e.g. `"unsigned.gg"`).
    pub trust_domain: String,
    /// Path portion after `spiffe://<trust_domain>/` (e.g. `"cluster/cygnus/ns/soma/sa/reflexd"`).
    pub path: String,
    /// Validated `/`-separated path segments.
    pub segments: Vec<String>,
    /// Seconds since the Unix epoch at which this SVID expires.
    pub exp_unix: u64,
    /// Optional RFC 8693 `act` delegation chain.
    pub act: Option<ActorClaim>,
    /// Optional OAuth 2.0 / WIMSE `scope` claim.
    pub scope: Option<String>,
}

impl VerifiedSpiffeIdentity {
    /// Return the path segment at `index`, if present.
    pub fn segment(&self, index: usize) -> Option<&str> {
        self.segments.get(index).map(String::as_str)
    }

    /// Return the full ordered delegation lineage (`[spiffe_id, act.sub, act.act.sub, ...]`).
    pub fn delegation_chain(&self) -> Vec<String> {
        let mut out = vec![self.spiffe_id.clone()];
        if let Some(ref act) = self.act {
            out.extend(act.delegation_chain());
        }
        out
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SvidError {
    #[error("not a JWT (three base64url parts expected)")]
    Malformed,
    #[error("unsupported alg (only ES256 and RS256 verify)")]
    UnknownAlgorithm,
    #[error("kid not in the JWKS, even after a refresh")]
    UnknownKeyId,
    #[error("signature does not verify")]
    BadSignature,
    #[error("aud does not contain this relying party")]
    WrongAudience,
    #[error("expired (no clock-skew grace)")]
    Expired,
    #[error("sub is not in this trust domain")]
    WrongTrustDomain,
    #[error("sub is not a host edge path (…/host/<host>/cortex-edge)")]
    WrongPath,
    #[error("RFC 8693 act delegation claim is empty or malformed")]
    InvalidDelegationClaim,
    #[error("RFC 8693 act delegation chain exceeds max depth of 8")]
    DelegationDepthExceeded,
    #[error("the JWKS source is unreachable — map to Unavailable, never to an auth refusal")]
    JwksUnavailable,
}

/// The JWT header field this verifier reads. The crate reads `alg` itself.
#[derive(Debug, serde::Deserialize)]
struct Header {
    kid: String,
}

/// A JSON Web Key, EC (P-256) or RSA, as the SPIRE OIDC provider serves it.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

/// A JWKS document (`{"keys": [...]}`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Where the JWKS comes from. Async (PR #146 review): an HTTP fetch inside
/// a sync trait would block a tonic worker. The cache handles freshness.
#[async_trait::async_trait]
pub trait JwksSource: Send + Sync {
    async fn fetch_jwks(&self) -> Result<Jwks, SvidError>;
}

/// The claims this verifier reads itself. `aud` and `exp` are enforced by the
/// rust-spiffe validator, which needs them in the token; `sub` picks the
/// trust domain and host before any key is looked up.
#[derive(Debug, serde::Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
    #[serde(default)]
    act: Option<ActorClaim>,
    #[serde(default)]
    scope: Option<String>,
}

/// Object-safe verifier seam: the EdgeBridge brain holds the verifier behind
/// `Arc<dyn SvidVerify>` so the service type needs no generic parameter.
#[async_trait::async_trait]
pub trait SvidVerify: Send + Sync {
    async fn verify(&self, token: &str) -> Result<VerifiedEdgeIdentity, SvidError>;
    async fn verify_wimse(&self, _token: &str) -> Result<VerifiedWimseIdentity, SvidError> {
        Err(SvidError::WrongPath)
    }
    async fn verify_with_policy(
        &self,
        _token: &str,
        _policy: &PathPolicy,
    ) -> Result<VerifiedSpiffeIdentity, SvidError> {
        Err(SvidError::WrongPath)
    }
    fn verify_cached(
        &self,
        _token: &str,
        _policy: &PathPolicy,
    ) -> Result<VerifiedSpiffeIdentity, SvidError> {
        Err(SvidError::JwksUnavailable)
    }
}

#[async_trait::async_trait]
impl<S: JwksSource> SvidVerify for SvidVerifier<S> {
    async fn verify(&self, token: &str) -> Result<VerifiedEdgeIdentity, SvidError> {
        SvidVerifier::verify(self, token).await
    }

    async fn verify_wimse(&self, token: &str) -> Result<VerifiedWimseIdentity, SvidError> {
        SvidVerifier::verify_wimse(self, token).await
    }

    async fn verify_with_policy(
        &self,
        token: &str,
        policy: &PathPolicy,
    ) -> Result<VerifiedSpiffeIdentity, SvidError> {
        SvidVerifier::verify_with_policy(self, token, policy).await
    }

    fn verify_cached(
        &self,
        token: &str,
        policy: &PathPolicy,
    ) -> Result<VerifiedSpiffeIdentity, SvidError> {
        SvidVerifier::verify_cached(self, token, policy)
    }
}

/// The JWT-SVID verifier. One per process; the cache is shared. One fetch
/// gate serves both paths (jury findings folded in): ANY fetch is refused
/// for 5s after a failure (a down provider is not a per-request retry loop),
/// and the 30s floor on FORCED refreshes (unknown-kid path) stamps only on a
/// SUCCESSFUL forced fetch — a failed one never blocks rotation recovery.
pub struct SvidVerifier<S: JwksSource> {
    source: S,
    audience: String,
    trust_domain: String,
    /// Minimum interval between successful FORCED refreshes.
    refresh_floor: Duration,
    /// No fetch of any kind within this window after a failure.
    failure_backoff: Duration,
    cache: Mutex<Option<Jwks>>,
    last_successful_forced: Mutex<Option<std::time::Instant>>,
    last_failed_fetch: Mutex<Option<std::time::Instant>>,
}

/// Lock a std mutex, recovering the data if a holder panicked. Every guarded
/// value here is a plain cache or timestamp, so a poisoned lock is still valid.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl<S: JwksSource> SvidVerifier<S> {
    pub fn new(source: S, audience: &str, trust_domain: &str) -> Self {
        // Pin the jsonwebtoken backend. If feature unification ever enables
        // both backends, its automatic choice panics on the first verify. An
        // Err only means a provider is already installed.
        let _ = jsonwebtoken::crypto::CryptoProvider::install_default(
            &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER,
        );
        Self {
            source,
            audience: audience.to_string(),
            trust_domain: trust_domain.to_string(),
            refresh_floor: Duration::from_secs(30),
            failure_backoff: Duration::from_secs(5),
            cache: Mutex::new(None),
            last_successful_forced: Mutex::new(None),
            last_failed_fetch: Mutex::new(None),
        }
    }

    /// Test/probe override for the failure backoff (a 5s sleep is not a test).
    pub fn with_failure_backoff(mut self, d: Duration) -> Self {
        self.failure_backoff = d;
        self
    }

    /// Synchronously seed or replace the cached JWKS (`CER-2603`).
    ///
    /// Synchronous callers (such as `soma`'s `reflexd` running on `tiny_http`)
    /// can populate the key cache from a background refresh thread or startup
    /// fetch and then call [`Self::verify_cached`] on the request thread
    /// without an async runtime.
    pub fn seed_jwks(&self, jwks: Jwks) {
        *lock(&self.cache) = Some(jwks);
    }

    /// The current key set: cached, else fetched and cached, behind one gate:
    /// no fetch within `failure_backoff` of a failure (both paths), and a
    /// forced refresh only when the last SUCCESSFUL one is past the floor.
    async fn jwks(&self, forced: bool) -> Result<Jwks, SvidError> {
        if !forced {
            if let Some(j) = lock(&self.cache).clone() {
                return Ok(j);
            }
        } else if lock(&self.last_successful_forced)
            .map(|t| t.elapsed() < self.refresh_floor)
            .unwrap_or(false)
        {
            // Within the floor: serve the stale cache (possibly nothing), no
            // fetch.
            return match lock(&self.cache).clone() {
                Some(j) => Ok(j),
                None => Err(SvidError::UnknownKeyId),
            };
        }
        // The unified failure backoff gates EVERY fetch kind.
        if lock(&self.last_failed_fetch)
            .map(|t| t.elapsed() < self.failure_backoff)
            .unwrap_or(false)
        {
            return Err(SvidError::JwksUnavailable);
        }
        // Stamp the forced floor BEFORE the await so concurrent verifies make
        // exactly one fetch; a FAILED fetch rolls the stamp back, so the
        // floor never blocks recovery (the failure backoff alone governs).
        if forced {
            *lock(&self.last_successful_forced) = Some(std::time::Instant::now());
        }
        match self.source.fetch_jwks().await {
            Ok(jwks) => {
                *lock(&self.cache) = Some(jwks.clone());
                Ok(jwks)
            }
            Err(e) => {
                if forced {
                    *lock(&self.last_successful_forced) = None;
                }
                *lock(&self.last_failed_fetch) = Some(std::time::Instant::now());
                Err(e)
            }
        }
    }

    /// Verify a JWT-SVID end to end: shape → trust domain → path shape → key
    /// lookup (one forced refresh on an unknown kid) → rust-spiffe validation
    /// (signature, aud, exp) → host.
    pub async fn verify(&self, token: &str) -> Result<VerifiedEdgeIdentity, SvidError> {
        let verified = self.verify_wimse(token).await?;
        let WimseIdentityKind::HostEdge { host } = verified.kind else {
            return Err(SvidError::WrongPath);
        };
        Ok(VerifiedEdgeIdentity {
            host,
            spiffe_id: verified.spiffe_id,
            exp_unix: verified.exp_unix,
        })
    }

    /// Verify a WIMSE JWT-SVID (`host/<host>/cortex-edge`, `agent/<team>/<agent_id>`,
    /// or `elf/<mesh>/<elf_id>`) and its optional RFC 8693 `act` delegation chain.
    pub async fn verify_wimse(&self, token: &str) -> Result<VerifiedWimseIdentity, SvidError> {
        let (header, claims) = parse(token)?;

        // Negative exp is nonsense (and would wrap a u64 cast); refuse it as
        // malformed (jury 3).
        let exp_unix = u64::try_from(claims.exp).map_err(|_| SvidError::Malformed)?;

        let spiffe = claims
            .sub
            .strip_prefix("spiffe://")
            .ok_or(SvidError::WrongPath)?;
        let (td, path) = spiffe.split_once('/').ok_or(SvidError::WrongPath)?;
        if td != self.trust_domain {
            return Err(SvidError::WrongTrustDomain);
        }

        let kind = parse_wimse_path(path)?;

        if let Some(ref act) = claims.act {
            act.validate(1)?;
        }

        // Only the two algs SPIRE signs with; the crates accept more.
        let alg = match jsonwebtoken::decode_header(token).map(|h| h.alg) {
            Ok(alg @ (Algorithm::ES256 | Algorithm::RS256)) => alg,
            _ => return Err(SvidError::UnknownAlgorithm),
        };

        let mut jwks = self.jwks(false).await?;
        if !jwks.keys.iter().any(|k| k.kid == header.kid) {
            // Unknown kid: the provider rotated. One forced refresh within the
            // floor, then refuse.
            jwks = self.jwks(true).await?;
        }
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid == header.kid)
            .ok_or(SvidError::UnknownKeyId)?;
        key_matches_alg(alg, jwk)?;

        // Signature, aud and exp: rust-spiffe, zero clock-skew leeway.
        let bundles = bundle_set(&self.trust_domain, &jwks)?;
        JwtSvid::parse_and_validate(token, &bundles, &[self.audience.as_str()])
            .map_err(map_jwt_svid_error)?;

        Ok(VerifiedWimseIdentity {
            kind,
            spiffe_id: claims.sub,
            exp_unix,
            act: claims.act,
            scope: claims.scope,
        })
    }

    /// Verify a neutral SPIFFE JWT-SVID against `policy` asynchronously (`CER-2603`),
    /// fetching or refreshing the JWKS on an unknown `kid`.
    pub async fn verify_with_policy(
        &self,
        token: &str,
        policy: &PathPolicy,
    ) -> Result<VerifiedSpiffeIdentity, SvidError> {
        let (header, claims, td, path, segments, exp_unix, alg) =
            self.prevalidate_with_policy(token, policy)?;

        let mut jwks = self.jwks(false).await?;
        if !jwks.keys.iter().any(|k| k.kid == header.kid) {
            jwks = self.jwks(true).await?;
        }
        self.finish_verify_with_jwks(
            token, header, claims, td, path, segments, exp_unix, alg, &jwks,
        )
    }

    /// Synchronously verify a neutral SPIFFE JWT-SVID against `policy` using
    /// the currently cached/seeded JWKS (`CER-2603`).
    ///
    /// Designed for synchronous HTTP servers (such as `soma`'s `reflexd` on `tiny_http`)
    /// that pre-seed keys via [`Self::seed_jwks`] (or a prior async fetch) and cannot
    /// `.await` on the request path. Returns [`SvidError::JwksUnavailable`] if no JWKS
    /// is cached, or [`SvidError::UnknownKeyId`] if `kid` is not in the cached set.
    pub fn verify_cached(
        &self,
        token: &str,
        policy: &PathPolicy,
    ) -> Result<VerifiedSpiffeIdentity, SvidError> {
        let (header, claims, td, path, segments, exp_unix, alg) =
            self.prevalidate_with_policy(token, policy)?;
        let jwks = lock(&self.cache)
            .clone()
            .ok_or(SvidError::JwksUnavailable)?;
        self.finish_verify_with_jwks(
            token, header, claims, td, path, segments, exp_unix, alg, &jwks,
        )
    }

    #[allow(clippy::type_complexity)]
    fn prevalidate_with_policy(
        &self,
        token: &str,
        policy: &PathPolicy,
    ) -> Result<(Header, Claims, String, String, Vec<String>, u64, Algorithm), SvidError> {
        let (header, claims) = parse(token)?;
        let exp_unix = u64::try_from(claims.exp).map_err(|_| SvidError::Malformed)?;

        let spiffe = claims
            .sub
            .strip_prefix("spiffe://")
            .ok_or(SvidError::WrongPath)?;
        let (td, path) = spiffe.split_once('/').ok_or(SvidError::WrongPath)?;
        if td != self.trust_domain {
            return Err(SvidError::WrongTrustDomain);
        }

        let segments = policy.validate_path(path)?;
        let td_str = td.to_string();
        let path_str = path.to_string();

        if let Some(ref act) = claims.act {
            act.validate(1)?;
        }

        let alg = match jsonwebtoken::decode_header(token).map(|h| h.alg) {
            Ok(alg @ (Algorithm::ES256 | Algorithm::RS256)) => alg,
            _ => return Err(SvidError::UnknownAlgorithm),
        };

        Ok((header, claims, td_str, path_str, segments, exp_unix, alg))
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_verify_with_jwks(
        &self,
        token: &str,
        header: Header,
        claims: Claims,
        trust_domain: String,
        path: String,
        segments: Vec<String>,
        exp_unix: u64,
        alg: Algorithm,
        jwks: &Jwks,
    ) -> Result<VerifiedSpiffeIdentity, SvidError> {
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid == header.kid)
            .ok_or(SvidError::UnknownKeyId)?;
        key_matches_alg(alg, jwk)?;

        let bundles = bundle_set(&self.trust_domain, jwks)?;
        JwtSvid::parse_and_validate(token, &bundles, &[self.audience.as_str()])
            .map_err(map_jwt_svid_error)?;

        Ok(VerifiedSpiffeIdentity {
            spiffe_id: claims.sub,
            trust_domain,
            path,
            segments,
            exp_unix,
            act: claims.act,
            scope: claims.scope,
        })
    }
}

/// Parse a SPIFFE path segment sequence into a [`WimseIdentityKind`].
fn parse_wimse_path(path: &str) -> Result<WimseIdentityKind, SvidError> {
    let segs: Vec<&str> = path.split('/').collect();
    match segs.as_slice() {
        ["host", h, "cortex-edge"] if valid_host_segment(h) => Ok(WimseIdentityKind::HostEdge {
            host: (*h).to_string(),
        }),
        ["agent", team, agent_id] if valid_host_segment(team) && valid_agent_segment(agent_id) => {
            Ok(WimseIdentityKind::Agent {
                team: (*team).to_string(),
                agent_id: (*agent_id).to_string(),
            })
        }
        ["elf", mesh, elf_id] if valid_host_segment(mesh) && valid_agent_segment(elf_id) => {
            Ok(WimseIdentityKind::ConclaveElf {
                mesh: (*mesh).to_string(),
                elf_id: (*elf_id).to_string(),
            })
        }
        _ => Err(SvidError::WrongPath),
    }
}

/// The trust domain's JWT authorities, as the rust-spiffe validator reads
/// them. A key the validator cannot load is left out, so a token that names
/// it is refused as an unknown kid.
fn bundle_set(trust_domain: &str, jwks: &Jwks) -> Result<JwtBundleSet, SvidError> {
    let td = TrustDomain::new(trust_domain).map_err(|_| SvidError::WrongTrustDomain)?;
    let mut bundle = JwtBundle::new(td);
    for jwk in &jwks.keys {
        if let Ok(json) = serde_json::to_vec(jwk) {
            let _ = bundle.add_jwk_authority_json(&json);
        }
    }
    let mut set = JwtBundleSet::default();
    set.add_bundle(bundle);
    Ok(set)
}

/// Map a rust-spiffe refusal onto this crate's taxonomy. The callers tell
/// "replay from another relying party" (WrongAudience) apart from a bad
/// signature, so the audience and expiry cases stay distinct.
fn map_jwt_svid_error(e: JwtSvidError) -> SvidError {
    use jsonwebtoken::errors::ErrorKind;
    match e {
        JwtSvidError::AuthorityNotFound(_) => SvidError::UnknownKeyId,
        JwtSvidError::BundleNotFound(_) => SvidError::WrongTrustDomain,
        JwtSvidError::InvalidAudience(..) => SvidError::WrongAudience,
        JwtSvidError::UnsupportedAlgorithm | JwtSvidError::BackendUnsupportedAlgorithm(_) => {
            SvidError::UnknownAlgorithm
        }
        JwtSvidError::BundleSourceError(_) => SvidError::JwksUnavailable,
        JwtSvidError::InvalidToken(e) => match e.kind() {
            ErrorKind::ExpiredSignature => SvidError::Expired,
            ErrorKind::InvalidAudience => SvidError::WrongAudience,
            ErrorKind::InvalidSignature => SvidError::BadSignature,
            ErrorKind::InvalidAlgorithm => SvidError::UnknownAlgorithm,
            _ => SvidError::Malformed,
        },
        _ => SvidError::Malformed,
    }
}

/// The key family and curve that `alg` needs. A key of another family, or an
/// EC key on another curve, is refused rather than coerced.
fn key_matches_alg(alg: Algorithm, jwk: &Jwk) -> Result<(), SvidError> {
    match (alg, jwk.kty.as_str(), jwk.crv.as_deref()) {
        (Algorithm::ES256, "EC", Some("P-256")) | (Algorithm::RS256, "RSA", _) => Ok(()),
        _ => Err(SvidError::UnknownAlgorithm),
    }
}

/// A host segment is a DNS-label-safe slug: [a-z0-9-]{1,63}. This refuses
/// `.`, `..`, %-encoded and uppercase forms by construction.
fn valid_host_segment(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 63
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// An agent or elf segment is a safe slug (`[a-z0-9_-]{1,63}`).
fn valid_agent_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Read the header and claims of a compact JWT. The signature is left to the
/// rust-spiffe validator.
fn parse(token: &str) -> Result<(Header, Claims), SvidError> {
    let mut parts = token.split('.');
    let (h, p) = (
        parts.next().ok_or(SvidError::Malformed)?,
        parts.next().ok_or(SvidError::Malformed)?,
    );
    parts.next().ok_or(SvidError::Malformed)?;
    if parts.next().is_some() {
        return Err(SvidError::Malformed);
    }
    let header: Header = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(h.as_bytes())
            .map_err(|_| SvidError::Malformed)?,
    )
    .map_err(|_| SvidError::Malformed)?;
    let claims: Claims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(p.as_bytes())
            .map_err(|_| SvidError::Malformed)?,
    )
    .map_err(|_| SvidError::Malformed)?;
    Ok((header, claims))
}

/// Test-support helpers, published for dependent crates behind the
/// `test-support` feature (cortex-api's edge tests mint through this;
/// blackwall/coral will too) and used by this crate's own tests. Locally
/// minted keys + SVIDs via openssl — no SPIRE anywhere.
#[cfg(any(test, feature = "test-support"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only key/SVID minting: a failure here is a failed test, not a runtime path"
)]
pub mod test_support {
    use super::*;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub type SignFn = Box<dyn Fn(&str) -> Vec<u8>>;

    pub struct TestKey {
        pub jwk: Jwk,
        sign: SignFn,
    }

    impl TestKey {
        pub fn es256(kid: &str) -> Self {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let ec = EcKey::generate(&group).unwrap();
            let point = ec
                .public_key()
                .to_bytes(
                    &group,
                    PointConversionForm::UNCOMPRESSED,
                    &mut openssl::bn::BigNumContext::new().unwrap(),
                )
                .unwrap();
            let (x, y) = (&point[1..33], &point[33..65]);
            let pkey = PKey::from_ec_key(ec).unwrap();
            Self {
                jwk: Jwk {
                    kty: "EC".into(),
                    kid: kid.into(),
                    crv: Some("P-256".into()),
                    x: Some(URL_SAFE_NO_PAD.encode(x)),
                    y: Some(URL_SAFE_NO_PAD.encode(y)),
                    n: None,
                    e: None,
                },
                sign: Box::new(move |input| {
                    let raw = Signer::new(MessageDigest::sha256(), &pkey)
                        .unwrap()
                        .sign_oneshot_to_vec(input.as_bytes())
                        .unwrap();
                    // openssl emits DER; JWT wants raw r‖s (32+32).
                    let dsig = openssl::ecdsa::EcdsaSig::from_der(&raw).unwrap();
                    let mut out = dsig.r().to_vec_padded(32).unwrap();
                    out.extend(dsig.s().to_vec_padded(32).unwrap());
                    out
                }),
            }
        }

        pub fn rs256(kid: &str) -> Self {
            let rsa = Rsa::generate(2048).unwrap();
            let jwk = Jwk {
                kty: "RSA".into(),
                kid: kid.into(),
                crv: None,
                x: None,
                y: None,
                n: Some(URL_SAFE_NO_PAD.encode(rsa.n().to_vec())),
                e: Some(URL_SAFE_NO_PAD.encode(rsa.e().to_vec())),
            };
            let pkey = PKey::from_rsa(rsa).unwrap();
            Self {
                jwk,
                sign: Box::new(move |input| {
                    Signer::new(MessageDigest::sha256(), &pkey)
                        .unwrap()
                        .sign_oneshot_to_vec(input.as_bytes())
                        .unwrap()
                }),
            }
        }
    }

    pub fn mint(key: &TestKey, alg: &str, sub: &str, aud: serde_json::Value, exp: i64) -> String {
        mint_wimse(key, alg, sub, aud, exp, None, None)
    }

    /// Sign any claim set with `key` (the same header as [`mint`]). For
    /// tokens that are not JWT-SVIDs, such as the Keycloak access tokens the
    /// enroll pod's operator mint verifies (CER-2265).
    pub fn mint_claims(key: &TestKey, alg: &str, claims: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD
            .encode(serde_json::json!({"alg": alg, "kid": key.jwk.kid, "typ": "JWT"}).to_string());
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let input = format!("{header}.{payload}");
        let sig = URL_SAFE_NO_PAD.encode((key.sign)(&input));
        format!("{input}.{sig}")
    }

    pub fn mint_wimse(
        key: &TestKey,
        alg: &str,
        sub: &str,
        aud: serde_json::Value,
        exp: i64,
        act: Option<ActorClaim>,
        scope: Option<&str>,
    ) -> String {
        let mut payload_obj = serde_json::json!({"sub": sub, "aud": aud, "exp": exp});
        if let Some(act_claim) = act {
            payload_obj["act"] = serde_json::to_value(act_claim).unwrap();
        }
        if let Some(sc) = scope {
            payload_obj["scope"] = serde_json::Value::String(sc.to_string());
        }
        mint_claims(key, alg, &payload_obj)
    }

    /// A source returning the given key sets in call order (refresh test).
    pub struct StaticJwks {
        pub pages: Mutex<Vec<Jwks>>,
    }

    impl StaticJwks {
        fn one(jwks: Jwks) -> Self {
            Self {
                pages: Mutex::new(vec![jwks.clone(), jwks]),
            }
        }
    }

    /// A source with a failure toggle (the reauth-outage test flips it
    /// mid-stream).
    pub struct ToggleJwks {
        pub jwks: Jwks,
        pub fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl JwksSource for ToggleJwks {
        async fn fetch_jwks(&self) -> Result<Jwks, SvidError> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                Err(SvidError::JwksUnavailable)
            } else {
                Ok(self.jwks.clone())
            }
        }
    }

    #[async_trait::async_trait]
    impl JwksSource for StaticJwks {
        async fn fetch_jwks(&self) -> Result<Jwks, SvidError> {
            let mut pages = self.pages.lock().unwrap();
            if pages.len() > 1 {
                Ok(pages.remove(0))
            } else {
                Ok(pages[0].clone())
            }
        }
    }

    pub const SUB: &str = "spiffe://unsigned.gg/host/ceres/cortex-edge";

    pub fn verifier(jwks: Jwks) -> SvidVerifier<StaticJwks> {
        SvidVerifier::new(StaticJwks::one(jwks), "cortex-edge-bridge", "unsigned.gg")
    }

    pub fn valid_claims() -> (serde_json::Value, i64) {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 300;
        (serde_json::json!(["cortex-edge-bridge"]), exp)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn a_valid_es256_svid_verifies_and_extracts_the_host() {
        let key = TestKey::es256("k1");
        let (aud, exp) = valid_claims();
        let token = mint(&key, "ES256", SUB, aud, exp);
        let v = verifier(Jwks {
            keys: vec![key.jwk.clone()],
        });
        let id = v.verify(&token).await.unwrap();
        assert_eq!(id.host, "ceres");
        assert_eq!(id.spiffe_id, SUB);
        assert_eq!(id.exp_unix, exp as u64);
    }

    #[tokio::test]
    async fn a_valid_rs256_svid_verifies() {
        let key = TestKey::rs256("k2");
        let (aud, exp) = valid_claims();
        let token = mint(&key, "RS256", SUB, aud, exp);
        let v = verifier(Jwks {
            keys: vec![key.jwk.clone()],
        });
        assert_eq!(v.verify(&token).await.unwrap().host, "ceres");
    }

    #[tokio::test]
    async fn aud_as_a_bare_string_also_counts() {
        let key = TestKey::es256("k1");
        let (_, exp) = valid_claims();
        let token = mint(
            &key,
            "ES256",
            SUB,
            serde_json::json!("cortex-edge-bridge"),
            exp,
        );
        let v = verifier(Jwks {
            keys: vec![key.jwk.clone()],
        });
        assert!(v.verify(&token).await.is_ok());
    }

    #[tokio::test]
    async fn a_replay_from_another_relying_party_is_rejected() {
        let key = TestKey::es256("k1");
        let (_, exp) = valid_claims();
        let token = mint(
            &key,
            "ES256",
            SUB,
            serde_json::json!(["blackwall-serve"]),
            exp,
        );
        let v = verifier(Jwks {
            keys: vec![key.jwk.clone()],
        });
        assert_eq!(
            v.verify(&token).await.unwrap_err(),
            SvidError::WrongAudience
        );
    }

    #[tokio::test]
    async fn a_wrong_trust_domain_is_rejected() {
        let key = TestKey::es256("k1");
        let (aud, exp) = valid_claims();
        let token = mint(
            &key,
            "ES256",
            "spiffe://evil.example/host/ceres/cortex-edge",
            aud,
            exp,
        );
        let v = verifier(Jwks {
            keys: vec![key.jwk.clone()],
        });
        assert_eq!(
            v.verify(&token).await.unwrap_err(),
            SvidError::WrongTrustDomain
        );
    }

    #[tokio::test]
    async fn a_wrong_path_shape_is_rejected() {
        let key = TestKey::es256("k1");
        let (aud, exp) = valid_claims();
        for sub in [
            "spiffe://unsigned.gg/ns/cortex/sa/cortex-api", // in-cluster shape
            "spiffe://unsigned.gg/host/ceres/other",        // wrong leaf
            "spiffe://unsigned.gg/host//cortex-edge",       // empty host
            "not-spiffe-at-all",
        ] {
            let token = mint(&key, "ES256", sub, aud.clone(), exp);
            let v = verifier(Jwks {
                keys: vec![key.jwk.clone()],
            });
            assert_eq!(
                v.verify(&token).await.unwrap_err(),
                SvidError::WrongPath,
                "sub {sub}"
            );
        }
    }

    #[tokio::test]
    async fn an_expired_svid_is_rejected_with_no_skew_grace() {
        let key = TestKey::es256("k1");
        let (aud, _) = valid_claims();
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 1; // one second past expiry; there is no grace
        let token = mint(&key, "ES256", SUB, aud, exp);
        let v = verifier(Jwks {
            keys: vec![key.jwk.clone()],
        });
        assert_eq!(v.verify(&token).await.unwrap_err(), SvidError::Expired);
    }

    #[tokio::test]
    async fn only_es256_and_rs256_are_accepted() {
        // The crates accept more SPIFFE algs (ES384, PS256, ...); SPIRE signs
        // with ES256 or RS256, so anything else is refused.
        let key = TestKey::es256("k1");
        let (aud, exp) = valid_claims();
        for alg in ["ES384", "PS256", "RS512", "HS256", "none"] {
            let token = mint(&key, alg, SUB, aud.clone(), exp);
            let v = verifier(Jwks {
                keys: vec![key.jwk.clone()],
            });
            assert_eq!(
                v.verify(&token).await.unwrap_err(),
                SvidError::UnknownAlgorithm,
                "alg {alg}"
            );
        }
    }

    #[tokio::test]
    async fn a_key_of_the_wrong_type_is_refused() {
        // A token whose kid names a key of the other family, or an EC key on
        // another curve: refuse, never coerce.
        let ec = TestKey::es256("k1");
        let rsa = TestKey::rs256("k1");
        let mut p384 = ec.jwk.clone();
        p384.crv = Some("P-384".into());
        let (aud, exp) = valid_claims();
        for (signer, alg, served) in [
            (&rsa, "RS256", ec.jwk.clone()),
            (&ec, "ES256", rsa.jwk.clone()),
            (&ec, "ES256", p384),
        ] {
            let token = mint(signer, alg, SUB, aud.clone(), exp);
            let v = verifier(Jwks { keys: vec![served] });
            assert_eq!(
                v.verify(&token).await.unwrap_err(),
                SvidError::UnknownAlgorithm,
                "{alg} token"
            );
        }
    }

    #[tokio::test]
    async fn a_tampered_payload_fails_the_signature() {
        let key = TestKey::es256("k1");
        let (aud, exp) = valid_claims();
        let token = mint(&key, "ES256", SUB, aud.clone(), exp);
        // Rewrite the payload AFTER signing: the signature no longer matches.
        let (h, _p, s) = {
            let mut it = token.split('.');
            (
                it.next().unwrap().to_string(),
                (),
                it.next_back().unwrap().to_string(),
            )
        };
        let forged = URL_SAFE_NO_PAD.encode(
            serde_json::json!({"sub": "spiffe://unsigned.gg/host/europa/cortex-edge", "aud": aud, "exp": exp})
                .to_string(),
        );
        let v = verifier(Jwks {
            keys: vec![key.jwk.clone()],
        });
        assert_eq!(
            v.verify(&format!("{h}.{forged}.{s}")).await.unwrap_err(),
            SvidError::BadSignature
        );
    }

    #[tokio::test]
    async fn an_unknown_kid_refreshes_once_then_serves() {
        let key = TestKey::es256("rotated");
        let (aud, exp) = valid_claims();
        let token = mint(&key, "ES256", SUB, aud, exp);
        // First fetch: empty (stale cache world); second: the rotated key.
        let v = SvidVerifier::new(
            StaticJwks {
                pages: Mutex::new(vec![
                    Jwks { keys: vec![] },
                    Jwks {
                        keys: vec![key.jwk.clone()],
                    },
                ]),
            },
            "cortex-edge-bridge",
            "unsigned.gg",
        );
        assert_eq!(v.verify(&token).await.unwrap().host, "ceres");
    }

    #[tokio::test]
    async fn a_kid_unknown_after_refresh_is_rejected() {
        let key = TestKey::es256("ghost");
        let (aud, exp) = valid_claims();
        let token = mint(&key, "ES256", SUB, aud, exp);
        let v = verifier(Jwks { keys: vec![] });
        assert_eq!(v.verify(&token).await.unwrap_err(), SvidError::UnknownKeyId);
    }

    /// A source that counts its fetches (the rate-limit test's probe).
    struct CountingJwks {
        fetches: Mutex<usize>,
        jwks: Jwks,
        /// Once the fetch count EXCEEDS this, fetches fail until cleared
        /// (outage probe; usize::MAX = never fail).
        fail_after: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl JwksSource for CountingJwks {
        async fn fetch_jwks(&self) -> Result<Jwks, SvidError> {
            let n = {
                let mut f = self.fetches.lock().unwrap();
                *f += 1;
                *f
            };
            if n > *self.fail_after.lock().unwrap() {
                return Err(SvidError::JwksUnavailable);
            }
            Ok(self.jwks.clone())
        }
    }

    #[tokio::test]
    async fn an_unknown_kid_storm_is_rate_limited() {
        // PR #146 review: an unknown kid must not fetch per request — a
        // replay storm would amplify traffic to the OIDC provider. Cold fetch
        // + ONE forced refresh, then the floor holds.
        let key = TestKey::es256("ghost");
        let (aud, exp) = valid_claims();
        let token = mint(&key, "ES256", SUB, aud, exp);
        let source = CountingJwks {
            fetches: Mutex::new(0),
            jwks: Jwks { keys: vec![] },
            fail_after: Mutex::new(usize::MAX), // never fail — the storm is unknown-kid, not outage
        };
        let v = SvidVerifier::new(source, "cortex-edge-bridge", "unsigned.gg");
        assert_eq!(v.verify(&token).await.unwrap_err(), SvidError::UnknownKeyId);
        assert_eq!(v.verify(&token).await.unwrap_err(), SvidError::UnknownKeyId);
        assert_eq!(v.verify(&token).await.unwrap_err(), SvidError::UnknownKeyId);
        assert_eq!(
            *v.source.fetches.lock().unwrap(),
            2,
            "cold fetch + one forced refresh — never one per request"
        );
    }

    #[tokio::test]
    async fn host_segments_must_be_dns_label_safe() {
        let key = TestKey::es256("k1");
        let (aud, exp) = valid_claims();
        for bad in ["Ceres", "..", "bad%20host", "a.b"] {
            let sub = format!("spiffe://unsigned.gg/host/{bad}/cortex-edge");
            let token = mint(&key, "ES256", &sub, aud.clone(), exp);
            let v = verifier(Jwks {
                keys: vec![key.jwk.clone()],
            });
            assert_eq!(
                v.verify(&token).await.unwrap_err(),
                SvidError::WrongPath,
                "host {bad}"
            );
        }
    }

    /// A source that is down.
    struct DownJwks;

    #[async_trait::async_trait]
    impl JwksSource for DownJwks {
        async fn fetch_jwks(&self) -> Result<Jwks, SvidError> {
            Err(SvidError::JwksUnavailable)
        }
    }

    #[tokio::test]
    async fn an_unreachable_jwks_source_maps_to_unavailable() {
        let key = TestKey::es256("k1");
        let (aud, exp) = valid_claims();
        let token = mint(&key, "ES256", SUB, aud, exp);
        let v = SvidVerifier::new(DownJwks, "cortex-edge-bridge", "unsigned.gg");
        assert_eq!(
            v.verify(&token).await.unwrap_err(),
            SvidError::JwksUnavailable
        );
    }

    // --- jury findings folded in post-merge (#146) ---------------------------

    #[tokio::test]
    async fn an_outage_storm_fetches_once_per_backoff_window() {
        // A down provider: N verifies must not be N fetches — one per
        // backoff window. (50ms backoff so the test never sleeps 5s.)
        let key = TestKey::es256("k1");
        let (aud, exp) = valid_claims();
        let token = mint(&key, "ES256", SUB, aud, exp);
        let source = CountingJwks {
            fetches: Mutex::new(0),
            jwks: Jwks { keys: vec![] },
            fail_after: Mutex::new(0), // every fetch fails
        };
        let v = SvidVerifier::new(source, "cortex-edge-bridge", "unsigned.gg")
            .with_failure_backoff(Duration::from_millis(50));
        for _ in 0..3 {
            assert_eq!(
                v.verify(&token).await.unwrap_err(),
                SvidError::JwksUnavailable
            );
        }
        assert_eq!(
            *v.source.fetches.lock().unwrap(),
            1,
            "three verifies in one backoff window must be ONE fetch"
        );
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            v.verify(&token).await.unwrap_err(),
            SvidError::JwksUnavailable
        );
        assert_eq!(*v.source.fetches.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn a_failed_forced_refresh_does_not_burn_the_floor() {
        // Cold fetch succeeds (empty set), the FORCED fetch fails: the floor
        // stamp rolls back, so recovery after the 50ms failure backoff is
        // free to fetch — never held by the 30s floor.
        let key = TestKey::es256("rotated");
        let (aud, exp) = valid_claims();
        let token = mint(&key, "ES256", SUB, aud, exp);
        let source = CountingJwks {
            fetches: Mutex::new(0),
            jwks: Jwks { keys: vec![] },
            fail_after: Mutex::new(1), // fetches AFTER the cold one fail
        };
        let v = SvidVerifier::new(source, "cortex-edge-bridge", "unsigned.gg")
            .with_failure_backoff(Duration::from_millis(50));
        // verify 1: cold fetch ok (empty) → kid unknown → forced fetch FAILS.
        assert_eq!(
            v.verify(&token).await.unwrap_err(),
            SvidError::JwksUnavailable
        );
        // verify 2, inside the 50ms failure backoff: no fetch at all.
        assert_eq!(
            v.verify(&token).await.unwrap_err(),
            SvidError::JwksUnavailable
        );
        assert_eq!(*v.source.fetches.lock().unwrap(), 2);
        // Recovery: the provider comes back, the backoff passes, and the
        // third verify FETCHES — the failed forced refresh burned no floor.
        *v.source.fail_after.lock().unwrap() = usize::MAX;
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(v.verify(&token).await.unwrap_err(), SvidError::UnknownKeyId);
        assert_eq!(
            *v.source.fetches.lock().unwrap(),
            3,
            "the forced refresh after a failed one must fetch — the floor was rolled back"
        );
    }

    #[tokio::test]
    async fn a_negative_exp_is_malformed() {
        let key = TestKey::es256("k1");
        let (aud, _) = valid_claims();
        let token = mint(&key, "ES256", SUB, aud, -1);
        let v = verifier(Jwks {
            keys: vec![key.jwk.clone()],
        });
        assert_eq!(v.verify(&token).await.unwrap_err(), SvidError::Malformed);
    }

    #[tokio::test]
    async fn wimse_agent_and_conclave_elf_svids_verify_with_rfc8693_act_delegation_chain() {
        let key = TestKey::es256("k-wimse");
        let (aud, exp) = valid_claims();
        let act = ActorClaim {
            sub: "spiffe://unsigned.gg/elf/research/oracle".to_string(),
            client_id: Some("elf-oracle".to_string()),
            act: Some(Box::new(ActorClaim {
                sub: "spiffe://unsigned.gg/agent/rd/coordinator_01".to_string(),
                client_id: None,
                act: None,
            })),
        };
        let agent_sub = "spiffe://unsigned.gg/agent/rd/hermes-worker-01";
        let token = mint_wimse(
            &key,
            "ES256",
            agent_sub,
            aud.clone(),
            exp,
            Some(act.clone()),
            Some("agent:execute mesh:send"),
        );
        let v = verifier(Jwks {
            keys: vec![key.jwk.clone()],
        });

        // Positive control: verify_wimse extracts Agent identity and delegation chain
        let verified = v.verify_wimse(&token).await.unwrap();
        assert_eq!(
            verified.kind,
            WimseIdentityKind::Agent {
                team: "rd".to_string(),
                agent_id: "hermes-worker-01".to_string(),
            }
        );
        assert_eq!(
            verified.delegation_chain(),
            vec![
                "spiffe://unsigned.gg/agent/rd/hermes-worker-01".to_string(),
                "spiffe://unsigned.gg/elf/research/oracle".to_string(),
                "spiffe://unsigned.gg/agent/rd/coordinator_01".to_string(),
            ]
        );
        assert_eq!(verified.scope.as_deref(), Some("agent:execute mesh:send"));

        // Negative control: host-edge-only `verify()` refuses an `agent/...` SVID as WrongPath
        assert_eq!(v.verify(&token).await.unwrap_err(), SvidError::WrongPath);

        // Positive control: Conclave Elf SVID (`spiffe://unsigned.gg/elf/estate/warden`)
        let elf_token = mint_wimse(
            &key,
            "ES256",
            "spiffe://unsigned.gg/elf/estate/warden",
            aud,
            exp,
            None,
            Some("elf:attest"),
        );
        let elf_verified = v.verify_wimse(&elf_token).await.unwrap();
        assert_eq!(
            elf_verified.kind,
            WimseIdentityKind::ConclaveElf {
                mesh: "estate".to_string(),
                elf_id: "warden".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn wimse_rejects_excessive_or_malformed_rfc8693_act_delegation_chains() {
        let key = TestKey::es256("k-act");
        let (aud, exp) = valid_claims();
        let v = verifier(Jwks {
            keys: vec![key.jwk.clone()],
        });

        // Build a 9-deep chain (exceeds MAX_DELEGATION_DEPTH = 8)
        let mut deep = ActorClaim {
            sub: "spiffe://unsigned.gg/agent/rd/root".to_string(),
            client_id: None,
            act: None,
        };
        for i in 0..MAX_DELEGATION_DEPTH {
            deep = ActorClaim {
                sub: format!("spiffe://unsigned.gg/agent/rd/hop-{i}"),
                client_id: None,
                act: Some(Box::new(deep)),
            };
        }
        let deep_token = mint_wimse(
            &key,
            "ES256",
            "spiffe://unsigned.gg/agent/rd/leaf",
            aud.clone(),
            exp,
            Some(deep),
            None,
        );
        assert_eq!(
            v.verify_wimse(&deep_token).await.unwrap_err(),
            SvidError::DelegationDepthExceeded
        );

        // Negative control: empty or whitespace-containing `act.sub`
        let bad_act = ActorClaim {
            sub: "spiffe://unsigned.gg/agent/rd/bad sub".to_string(),
            client_id: None,
            act: None,
        };
        let bad_token = mint_wimse(
            &key,
            "ES256",
            "spiffe://unsigned.gg/agent/rd/leaf",
            aud,
            exp,
            Some(bad_act),
            None,
        );
        assert_eq!(
            v.verify_wimse(&bad_token).await.unwrap_err(),
            SvidError::InvalidDelegationClaim
        );
    }

    #[test]
    fn verify_cached_validates_generic_spiffe_id_synchronously_for_soma_reflexd() {
        let key = TestKey::es256("k-sync-soma");
        let (_, exp) = valid_claims();
        let sub = "spiffe://unsigned.gg/cluster/cygnus/ns/soma/sa/reflexd";
        let token = mint_wimse(
            &key,
            "ES256",
            sub,
            serde_json::json!(["soma-reflexd"]),
            exp,
            Some(ActorClaim {
                sub: "spiffe://unsigned.gg/agent/rd/caller-01".to_string(),
                client_id: None,
                act: None,
            }),
            Some("soma:reflex"),
        );

        let v = SvidVerifier::new(
            StaticJwks {
                pages: Mutex::new(vec![Jwks { keys: vec![] }]),
            },
            "soma-reflexd",
            "unsigned.gg",
        );
        let policy = PathPolicy::Pattern("cluster/cygnus/ns/*/sa/*".to_string());

        // Negative control 1: unseeded cache returns JwksUnavailable synchronously.
        assert_eq!(
            v.verify_cached(&token, &policy).unwrap_err(),
            SvidError::JwksUnavailable
        );

        // Seed JWKS with a different key first: returns UnknownKeyId.
        let other = TestKey::es256("k-other");
        v.seed_jwks(Jwks {
            keys: vec![other.jwk],
        });
        assert_eq!(
            v.verify_cached(&token, &policy).unwrap_err(),
            SvidError::UnknownKeyId
        );

        // Positive control: seed the matching key and verify synchronously without tokio.
        v.seed_jwks(Jwks {
            keys: vec![key.jwk],
        });
        let id = v.verify_cached(&token, &policy).unwrap();
        assert_eq!(id.spiffe_id, sub);
        assert_eq!(id.trust_domain, "unsigned.gg");
        assert_eq!(id.path, "cluster/cygnus/ns/soma/sa/reflexd");
        assert_eq!(
            id.segments,
            vec!["cluster", "cygnus", "ns", "soma", "sa", "reflexd"]
        );
        assert_eq!(id.segment(3), Some("soma"));
        assert_eq!(id.segment(5), Some("reflexd"));
        assert_eq!(id.segment(6), None);
        assert_eq!(id.scope.as_deref(), Some("soma:reflex"));
        assert_eq!(
            id.delegation_chain(),
            vec![
                sub.to_string(),
                "spiffe://unsigned.gg/agent/rd/caller-01".to_string()
            ]
        );

        // Also works via SvidVerify trait object synchronously.
        let trait_obj: &dyn SvidVerify = &v;
        let via_trait = trait_obj.verify_cached(&token, &policy).unwrap();
        assert_eq!(via_trait, id);

        // Negative control 2: wrong pattern is rejected as WrongPath.
        let wrong_pattern = PathPolicy::Pattern("cluster/other/ns/*/sa/*".to_string());
        assert_eq!(
            v.verify_cached(&token, &wrong_pattern).unwrap_err(),
            SvidError::WrongPath
        );
    }

    #[tokio::test]
    async fn verify_with_policy_supports_all_path_policies_and_rotates_jwks() {
        let k1 = TestKey::es256("k-pol-1");
        let k2 = TestKey::es256("k-pol-2");
        let (aud, exp) = valid_claims();
        let sub = "spiffe://unsigned.gg/cluster/cygnus/ns/soma/sa/reflexd";
        let token = mint(&k2, "ES256", sub, aud, exp);

        let v = SvidVerifier::new(
            StaticJwks {
                pages: Mutex::new(vec![
                    Jwks {
                        keys: vec![k1.jwk.clone()],
                    },
                    Jwks {
                        keys: vec![k1.jwk, k2.jwk],
                    },
                ]),
            },
            "cortex-edge-bridge",
            "unsigned.gg",
        );

        // AnyNonEmpty
        let id = v
            .verify_with_policy(&token, &PathPolicy::AnyNonEmpty)
            .await
            .unwrap();
        assert_eq!(id.segments.len(), 6);

        // ExactSegments matching and non-matching
        assert!(v
            .verify_with_policy(&token, &PathPolicy::ExactSegments { count: 6 })
            .await
            .is_ok());
        assert_eq!(
            v.verify_with_policy(&token, &PathPolicy::ExactSegments { count: 3 })
                .await
                .unwrap_err(),
            SvidError::WrongPath
        );

        // PrefixSegments matching and non-matching
        assert!(v
            .verify_with_policy(
                &token,
                &PathPolicy::PrefixSegments(vec!["cluster".into(), "cygnus".into(), "ns".into()])
            )
            .await
            .is_ok());
        assert_eq!(
            v.verify_with_policy(
                &token,
                &PathPolicy::PrefixSegments(vec!["host".into(), "ceres".into()])
            )
            .await
            .unwrap_err(),
            SvidError::WrongPath
        );
    }
}
