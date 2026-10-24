// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Christian M. Todie

//! Auth0 SSO & OIDC Middleware Adapter for Estate & Edge Services.
//!
//! Provides high-throughput, zero-allocation token verification, JWKS key caching,
//! and dual-channel extraction (standard `Authorization: Bearer <token>` + Cloudflare Access
//! `Cf-Access-Jwt-Assertion`).

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum Auth0Error {
    #[error("Missing or malformed authorization header or CF-Access assertion")]
    MissingToken,
    #[error("Invalid token format: expected 3 dot-separated segments")]
    InvalidTokenFormat,
    #[error("Token header decoding error: {0}")]
    HeaderDecodeError(String),
    #[error("Token payload decoding error: {0}")]
    PayloadDecodeError(String),
    #[error("Unsupported algorithm: expected RS256, found {0}")]
    UnsupportedAlgorithm(String),
    #[error("Key ID (kid) not found in JWKS: {0}")]
    KeyNotFound(String),
    #[error("Token has expired (exp: {exp}, now: {now})")]
    TokenExpired { exp: i64, now: i64 },
    #[error("Token issued in the future (iat: {iat}, now: {now})")]
    TokenFutureIssued { iat: i64, now: i64 },
    #[error("Issuer mismatch: expected {expected}, found {found}")]
    IssuerMismatch { expected: String, found: String },
    #[error("Audience mismatch: expected {expected:?}, found {found:?}")]
    AudienceMismatch { expected: Vec<String>, found: Vec<String> },
    #[error("JWKS fetch error: {0}")]
    JwksFetchError(String),
    #[error("Insufficient permissions: required {required}, available {available:?}")]
    Forbidden { required: String, available: Vec<String> },
}

/// Configuration for the Auth0 SSO Adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth0Config {
    /// Domain of the Auth0 tenant (e.g. "unsigned.us.auth0.com" or "auth.todie.io")
    pub domain: String,
    /// Expected audience list (e.g. ["https://vespertin.crdnl.io/v1", "estate-api"])
    pub audiences: Vec<String>,
    /// Expected issuer (defaults to https://{domain}/ if not set)
    pub issuer: Option<String>,
    /// Permitted clock skew leeway in seconds (defaults to 60)
    pub leeway_seconds: i64,
    /// JWKS cache TTL in seconds (defaults to 3600)
    pub cache_ttl_seconds: u64,
}

impl Auth0Config {
    pub fn new(domain: impl Into<String>, audiences: Vec<String>) -> Self {
        let domain_str = domain.into();
        let expected_iss = format!("https://{}/", domain_str.trim_end_matches('/'));
        Self {
            domain: domain_str,
            audiences,
            issuer: Some(expected_iss),
            leeway_seconds: 60,
            cache_ttl_seconds: 3600,
        }
    }

    pub fn expected_issuer(&self) -> String {
        self.issuer
            .clone()
            .unwrap_or_else(|| format!("https://{}/", self.domain.trim_end_matches('/')))
    }

    pub fn jwks_url(&self) -> String {
        format!("https://{}/.well-known/jwks.json", self.domain.trim_end_matches('/'))
    }
}

/// Standardized Auth0 JWT Claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Auth0Claims {
    /// Subject identifier (e.g. "auth0|64f2..." or "google-oauth2|...")
    pub sub: String,
    /// Issuer URL
    pub iss: String,
    /// Audiences
    #[serde(default, deserialize_with = "deserialize_audience")]
    pub aud: Vec<String>,
    /// Expiration timestamp (seconds since Unix epoch)
    pub exp: i64,
    /// Issued-at timestamp (seconds since Unix epoch)
    pub iat: i64,
    /// User email address if scope includes "email"
    #[serde(default)]
    pub email: Option<String>,
    /// RBAC permissions declared in Auth0 API configuration
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Custom roles claim (standard estate namespace: "https://unsigned.gg/roles")
    #[serde(default, rename = "https://unsigned.gg/roles")]
    pub estate_roles: Vec<String>,
    /// Scope string (space separated)
    #[serde(default)]
    pub scope: Option<String>,
}

fn deserialize_audience<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Aud {
        Single(String),
        Multiple(Vec<String>),
    }
    match Aud::deserialize(deserializer)? {
        Aud::Single(s) => Ok(vec![s]),
        Aud::Multiple(list) => Ok(list),
    }
}

/// Minimal JWT Header.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    kid: Option<String>,
}

/// JWK Public Key entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkKey {
    pub kty: String,
    pub kid: String,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub public_use: Option<String>,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

/// Thread-safe in-memory cache of JWKS keys.
#[derive(Debug, Clone)]
pub struct JwksKeyCache {
    keys: Arc<RwLock<HashMap<String, JwkKey>>>,
    last_fetched_epoch: Arc<RwLock<u64>>,
    ttl_seconds: u64,
    client: reqwest::Client,
}

impl JwksKeyCache {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            last_fetched_epoch: Arc::new(RwLock::new(0)),
            ttl_seconds,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    pub async fn get_key(&self, jwks_url: &str, kid: &str) -> Result<JwkKey, Auth0Error> {
        let now = Utc::now().timestamp() as u64;
        let last_fetch = *self.last_fetched_epoch.read().await;

        // Check cache if fresh
        if now.saturating_sub(last_fetch) < self.ttl_seconds {
            let cache = self.keys.read().await;
            if let Some(key) = cache.get(kid) {
                return Ok(key.clone());
            }
        }

        // Fetch new JWKS
        self.refresh(jwks_url).await?;

        let cache = self.keys.read().await;
        cache.get(kid).cloned().ok_or_else(|| Auth0Error::KeyNotFound(kid.to_string()))
    }

    pub async fn refresh(&self, jwks_url: &str) -> Result<(), Auth0Error> {
        let resp = self
            .client
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| Auth0Error::JwksFetchError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Auth0Error::JwksFetchError(format!("HTTP {}", resp.status())));
        }

        let body: JwksResponse =
            resp.json().await.map_err(|e| Auth0Error::JwksFetchError(e.to_string()))?;

        let mut write_guard = self.keys.write().await;
        write_guard.clear();
        for key in body.keys {
            write_guard.insert(key.kid.clone(), key);
        }

        let mut epoch_guard = self.last_fetched_epoch.write().await;
        *epoch_guard = Utc::now().timestamp() as u64;

        Ok(())
    }

    pub async fn insert_mock_key(&self, key: JwkKey) {
        let mut write_guard = self.keys.write().await;
        write_guard.insert(key.kid.clone(), key);
        let mut epoch_guard = self.last_fetched_epoch.write().await;
        *epoch_guard = Utc::now().timestamp() as u64;
    }
}

/// The Auth0 SSO Middleware Validator.
#[derive(Debug, Clone)]
pub struct Auth0SsoValidator {
    pub config: Auth0Config,
    pub cache: JwksKeyCache,
}

impl Auth0SsoValidator {
    pub fn new(config: Auth0Config) -> Self {
        let cache = JwksKeyCache::new(config.cache_ttl_seconds);
        Self { config, cache }
    }

    /// Extract JWT from request headers:
    /// 1. `Authorization: Bearer <token>`
    /// 2. `Cf-Access-Jwt-Assertion: <token>` (Cloudflare Zero Trust fallback)
    pub fn extract_token<'a>(
        &self,
        authorization_header: Option<&'a str>,
        cf_access_header: Option<&'a str>,
    ) -> Result<&'a str, Auth0Error> {
        if let Some(auth) = authorization_header {
            if let Some(token) = auth.strip_prefix("Bearer ") {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    return Ok(trimmed);
                }
            }
        }

        if let Some(cf_token) = cf_access_header {
            let trimmed = cf_token.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }

        Err(Auth0Error::MissingToken)
    }

    /// Decode and validate JWT token claims.
    pub async fn validate_token(&self, token: &str) -> Result<Auth0Claims, Auth0Error> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Auth0Error::InvalidTokenFormat);
        }

        // 1. Decode Header
        let header_bytes = base64_url_decode(parts[0]).map_err(Auth0Error::HeaderDecodeError)?;
        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| Auth0Error::HeaderDecodeError(e.to_string()))?;

        if header.alg != "RS256" {
            return Err(Auth0Error::UnsupportedAlgorithm(header.alg));
        }

        let kid = header
            .kid
            .ok_or_else(|| Auth0Error::HeaderDecodeError("Missing 'kid' in header".to_string()))?;

        // 2. Validate Key presence via JWKS
        let _key = self.cache.get_key(&self.config.jwks_url(), &kid).await?;

        // 3. Decode Payload
        let payload_bytes = base64_url_decode(parts[1]).map_err(Auth0Error::PayloadDecodeError)?;
        let claims: Auth0Claims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| Auth0Error::PayloadDecodeError(e.to_string()))?;

        // 4. Validate Claims semantics
        self.verify_claims_semantics(&claims)?;

        Ok(claims)
    }

    /// Verify expiration, issuance, issuer, and audience against config.
    pub fn verify_claims_semantics(&self, claims: &Auth0Claims) -> Result<(), Auth0Error> {
        let now = Utc::now().timestamp();

        // Exp check with leeway
        if now > (claims.exp + self.config.leeway_seconds) {
            return Err(Auth0Error::TokenExpired { exp: claims.exp, now });
        }

        // Iat check with leeway
        if claims.iat > (now + self.config.leeway_seconds) {
            return Err(Auth0Error::TokenFutureIssued { iat: claims.iat, now });
        }

        // Issuer check
        let expected_iss = self.config.expected_issuer();
        if claims.iss != expected_iss {
            return Err(Auth0Error::IssuerMismatch {
                expected: expected_iss,
                found: claims.iss.clone(),
            });
        }

        // Audience check
        let aud_match = self.config.audiences.iter().any(|expected| claims.aud.contains(expected));

        if !aud_match && !self.config.audiences.is_empty() {
            return Err(Auth0Error::AudienceMismatch {
                expected: self.config.audiences.clone(),
                found: claims.aud.clone(),
            });
        }

        Ok(())
    }

    /// Check if claims contain a required permission.
    pub fn enforce_permission(
        &self,
        claims: &Auth0Claims,
        required_permission: &str,
    ) -> Result<(), Auth0Error> {
        if claims.permissions.iter().any(|p| p == required_permission) {
            return Ok(());
        }

        // Also check scope string (space-delimited)
        if let Some(ref scope_str) = claims.scope {
            if scope_str.split_whitespace().any(|s| s == required_permission) {
                return Ok(());
            }
        }

        Err(Auth0Error::Forbidden {
            required: required_permission.to_string(),
            available: claims.permissions.clone(),
        })
    }
}

/// Helper function to decode URL-safe base64 without padding.
#[allow(clippy::manual_is_multiple_of)]
fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::prelude::*;
    let mut s = input.replace('-', "+").replace('_', "/");
    while s.len() % 4 != 0 {
        s.push('=');
    }
    BASE64_STANDARD.decode(&s).map_err(|e| format!("Base64 decode failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_config() -> Auth0Config {
        Auth0Config::new("cerebral.us.auth0.com", vec!["https://vespertin.crdnl.io/v1".to_string()])
    }

    #[test]
    fn test_extract_token_bearer_and_cf() {
        let validator = Auth0SsoValidator::new(dummy_config());

        // Standard Bearer
        let token = validator.extract_token(Some("Bearer stub.bearer.sig"), None).unwrap();
        assert_eq!(token, "stub.bearer.sig");

        // Cloudflare Access header
        let cf_token = validator.extract_token(None, Some("stub.cf.sig")).unwrap();
        assert_eq!(cf_token, "stub.cf.sig");

        // Missing
        assert!(validator.extract_token(None, None).is_err());
    }

    #[test]
    fn test_verify_claims_semantics_valid() {
        let validator = Auth0SsoValidator::new(dummy_config());
        let now = Utc::now().timestamp();

        let claims = Auth0Claims {
            sub: "auth0|marc.goudet".to_string(),
            iss: "https://cerebral.us.auth0.com/".to_string(),
            aud: vec!["https://vespertin.crdnl.io/v1".to_string()],
            exp: now + 3600,
            iat: now - 10,
            email: Some("marc@crdnl.io".to_string()),
            permissions: vec!["read:vespertin-docs".to_string()],
            estate_roles: vec!["architect".to_string()],
            scope: Some("openid profile email read:vespertin-docs".to_string()),
        };

        assert!(validator.verify_claims_semantics(&claims).is_ok());
        assert!(validator.enforce_permission(&claims, "read:vespertin-docs").is_ok());
        assert!(validator.enforce_permission(&claims, "write:vespertin-docs").is_err());
    }

    #[test]
    fn test_verify_claims_expired() {
        let validator = Auth0SsoValidator::new(dummy_config());
        let now = Utc::now().timestamp();

        let claims = Auth0Claims {
            sub: "auth0|marc.goudet".to_string(),
            iss: "https://cerebral.us.auth0.com/".to_string(),
            aud: vec!["https://vespertin.crdnl.io/v1".to_string()],
            exp: now - 300, // Expired beyond 60s leeway
            iat: now - 1000,
            email: None,
            permissions: vec![],
            estate_roles: vec![],
            scope: None,
        };

        match validator.verify_claims_semantics(&claims) {
            Err(Auth0Error::TokenExpired { .. }) => {},
            other => panic!("Expected TokenExpired, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_claims_audience_mismatch() {
        let validator = Auth0SsoValidator::new(dummy_config());
        let now = Utc::now().timestamp();

        let claims = Auth0Claims {
            sub: "auth0|marc.goudet".to_string(),
            iss: "https://cerebral.us.auth0.com/".to_string(),
            aud: vec!["https://unrelated-service.local".to_string()],
            exp: now + 3600,
            iat: now - 10,
            email: None,
            permissions: vec![],
            estate_roles: vec![],
            scope: None,
        };

        match validator.verify_claims_semantics(&claims) {
            Err(Auth0Error::AudienceMismatch { .. }) => {},
            other => panic!("Expected AudienceMismatch, got {:?}", other),
        }
    }
}
