//  Copyright (c) 2026 Airbus SAS
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Airbus SAS - initial API and implementation
//

//! Subject tokens issued by trusted external OIDC providers.
//!
//! Workloads outside the cluster have no Kubernetes service account token. They can instead present a
//! token from an OIDC provider the operator trusts (e.g. a client-credentials token from Keycloak).
//! [`TrustedIssuerVerifier`] verifies such a token locally against the provider's JWKS, and
//! [`IssuerRoutingVerifier`] picks that verifier by the token's `iss`, falling back to the Kubernetes
//! TokenReview verifier for every other token.
//!
//! The verified subject is namespaced with the issuer's configured prefix before it is used as the
//! client identifier for resource mappings, so an external subject can never collide with a Kubernetes
//! service account (`system:serviceaccount:...`) or with a subject of another trusted issuer.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use bon::Builder;
use dsdk_facet_core::jwt::JwtVerificationError::{InvalidFormat, VerificationFailed};
use dsdk_facet_core::jwt::{JwtVerificationError, JwtVerifier, TokenClaims};
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

/// How long a fetched JWKS is used before it is fetched again.
pub const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Claim that carries the subject by default.
pub const DEFAULT_SUBJECT_CLAIM: &str = "sub";

/// Subject prefix reserved by Kubernetes; an external prefix must never start with it.
pub const RESERVED_SUBJECT_PREFIX: &str = "system:";

/// A token signed with a key that is not in the cached JWKS triggers a refetch (the provider may have
/// rotated its keys), but at most once per this interval so unknown `kid`s cannot be used to flood the
/// provider.
const MIN_JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Asymmetric algorithms accepted on external tokens. Symmetric algorithms are never accepted: the
/// verification key would also be a signing key.
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Verifies tokens of one trusted external OIDC issuer against its JWKS.
///
/// Checks the signature, `iss` (must equal the configured issuer), `aud` (must contain the audience
/// passed to [`JwtVerifier::verify_token`]), `exp` and `nbf`. The returned `sub` is the configured
/// prefix followed by the value of the subject claim; `iss` is the external issuer.
#[derive(Builder)]
pub struct TrustedIssuerVerifier {
    /// Expected `iss` of the tokens, e.g. `https://idp.example.com/realms/example`.
    #[builder(into)]
    issuer: String,

    /// URL of the issuer's JSON Web Key Set.
    #[builder(into)]
    jwks_url: String,

    /// Prepended to the subject to form the client identifier, e.g. `external-idp:`.
    #[builder(into)]
    subject_prefix: String,

    /// Claim that identifies the caller. Client-credentials tokens of some providers carry the client
    /// in `azp` or `client_id` rather than in `sub`.
    #[builder(into, default = DEFAULT_SUBJECT_CLAIM)]
    subject_claim: String,

    #[builder(default = DEFAULT_JWKS_CACHE_TTL)]
    jwks_cache_ttl: Duration,

    /// Clock skew tolerated on `exp` and `nbf`.
    #[builder(default = 60)]
    leeway_secs: u64,

    #[builder(default = Client::new())]
    client: Client,

    #[builder(skip)]
    cache: RwLock<Option<CachedJwks>>,
}

struct CachedJwks {
    keys: HashMap<String, Jwk>,
    fetched_at: Instant,
}

impl TrustedIssuerVerifier {
    /// Returns the key with the given `kid`, fetching the JWKS when the cache is empty or expired, or
    /// when the key is unknown and the cache was not refreshed within [`MIN_JWKS_REFRESH_INTERVAL`].
    async fn key(&self, kid: &str) -> Result<Jwk, JwtVerificationError> {
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                let age = cached.fetched_at.elapsed();
                if age < self.jwks_cache_ttl
                    && let Some(key) = cached.keys.get(kid)
                {
                    return Ok(key.clone());
                }
                if age < MIN_JWKS_REFRESH_INTERVAL.min(self.jwks_cache_ttl) {
                    return Err(unknown_kid(kid));
                }
            }
        }

        let mut cache = self.cache.write().await;
        // Another request may have refreshed the cache while this one waited for the lock.
        if let Some(cached) = cache.as_ref()
            && cached.fetched_at.elapsed() < MIN_JWKS_REFRESH_INTERVAL.min(self.jwks_cache_ttl)
        {
            return cached.keys.get(kid).cloned().ok_or_else(|| unknown_kid(kid));
        }

        let fetched = self.fetch_jwks().await?;
        let key = fetched.keys.get(kid).cloned();
        *cache = Some(fetched);
        key.ok_or_else(|| unknown_kid(kid))
    }

    async fn fetch_jwks(&self) -> Result<CachedJwks, JwtVerificationError> {
        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| VerificationFailed(format!("Failed to fetch JWKS of issuer '{}': {e}", self.issuer)))?;
        if !response.status().is_success() {
            return Err(VerificationFailed(format!(
                "JWKS endpoint of issuer '{}' returned status {}",
                self.issuer,
                response.status()
            )));
        }
        let raw: RawJwkSet = response
            .json()
            .await
            .map_err(|e| VerificationFailed(format!("Invalid JWKS of issuer '{}': {e}", self.issuer)))?;

        // Parse keys one by one: a provider may publish key types this library does not know, which
        // must not make the other keys unusable.
        let mut keys = HashMap::new();
        for value in raw.keys {
            match serde_json::from_value::<Jwk>(value) {
                Ok(jwk) => {
                    if let Some(kid) = jwk.common.key_id.clone() {
                        keys.insert(kid, jwk);
                    }
                }
                Err(e) => warn!(issuer = %self.issuer, "skipping unsupported JWKS entry: {e}"),
            }
        }

        Ok(CachedJwks {
            keys,
            fetched_at: Instant::now(),
        })
    }
}

#[async_trait]
impl JwtVerifier for TrustedIssuerVerifier {
    async fn verify_token(&self, audience: &str, token: &str) -> Result<TokenClaims, JwtVerificationError> {
        let header = decode_header(token).map_err(|_| InvalidFormat)?;
        if !ALLOWED_ALGORITHMS.contains(&header.alg) {
            return Err(VerificationFailed(format!(
                "algorithm {:?} is not accepted",
                header.alg
            )));
        }
        let kid = header.kid.ok_or(InvalidFormat)?;

        let jwk = self.key(&kid).await?;
        if jwk.common.public_key_use == Some(PublicKeyUse::Encryption) {
            return Err(VerificationFailed(format!("key '{kid}' is not a signing key")));
        }
        // A key pinned to an algorithm must not be used with another one. The two enums share their
        // JOSE names, which is what their serde representation produces.
        if let Some(key_alg) = &jwk.common.key_algorithm
            && serde_json::to_value(key_alg).ok() != serde_json::to_value(header.alg).ok()
        {
            return Err(VerificationFailed(format!(
                "key '{kid}' is not meant for algorithm {:?}",
                header.alg
            )));
        }
        let decoding_key =
            DecodingKey::from_jwk(&jwk).map_err(|e| VerificationFailed(format!("Failed to load key '{kid}': {e}")))?;

        let mut validation = Validation::new(header.alg);
        validation.leeway = self.leeway_secs;
        validation.validate_nbf = true;
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);

        let data = decode::<Map<String, Value>>(token, &decoding_key, &validation).map_err(|e| match e.kind() {
            ErrorKind::ExpiredSignature => JwtVerificationError::TokenExpired,
            ErrorKind::ImmatureSignature => JwtVerificationError::TokenNotYetValid,
            ErrorKind::InvalidSignature => JwtVerificationError::InvalidSignature,
            ErrorKind::InvalidToken => InvalidFormat,
            _ => VerificationFailed(e.to_string()),
        })?;
        let claims = data.claims;

        let subject = claims
            .get(&self.subject_claim)
            .and_then(Value::as_str)
            .ok_or_else(|| VerificationFailed(format!("token has no '{}' claim", self.subject_claim)))?;
        if subject.is_empty() || subject.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(VerificationFailed(format!(
                "claim '{}' is not a valid subject",
                self.subject_claim
            )));
        }

        Ok(TokenClaims {
            sub: format!("{}{subject}", self.subject_prefix),
            iss: self.issuer.clone(),
            aud: audience.to_string(),
            iat: claims.get("iat").and_then(Value::as_i64).unwrap_or(0),
            exp: claims.get("exp").and_then(Value::as_i64).unwrap_or(0),
            nbf: claims.get("nbf").and_then(Value::as_i64),
            custom: Map::new(),
        })
    }
}

/// Routes a token to the verifier of its trusted issuer, or to the default verifier.
///
/// The `iss` claim is read without verification only to pick a verifier; the picked verifier then
/// checks the token in full, including that `iss` is its own issuer. A forged `iss` therefore only
/// selects which verifier rejects the token.
#[derive(Builder)]
pub struct IssuerRoutingVerifier {
    /// Verifies every token whose `iss` is not a trusted issuer (the Kubernetes TokenReview verifier).
    default: Box<dyn JwtVerifier>,

    #[builder(default)]
    trusted: HashMap<String, TrustedIssuerVerifier>,
}

#[async_trait]
impl JwtVerifier for IssuerRoutingVerifier {
    async fn verify_token(&self, audience: &str, token: &str) -> Result<TokenClaims, JwtVerificationError> {
        match unverified_issuer(token).and_then(|iss| self.trusted.get(&iss)) {
            Some(verifier) => verifier.verify_token(audience, token).await,
            None => self.default.verify_token(audience, token).await,
        }
    }
}

/// Builds the routing table from trusted issuer verifiers, keyed by their issuer.
pub fn trusted_issuer_map(
    verifiers: impl IntoIterator<Item = TrustedIssuerVerifier>,
) -> HashMap<String, TrustedIssuerVerifier> {
    verifiers.into_iter().map(|v| (v.issuer.clone(), v)).collect()
}

#[derive(Deserialize)]
struct RawJwkSet {
    keys: Vec<Value>,
}

#[derive(Deserialize)]
struct IssuerOnly {
    iss: Option<String>,
}

fn unverified_issuer(token: &str) -> Option<String> {
    insecure_decode::<IssuerOnly>(token).ok()?.claims.iss
}

fn unknown_kid(kid: &str) -> JwtVerificationError {
    VerificationFailed(format!("no key '{kid}' in the issuer's JWKS"))
}
