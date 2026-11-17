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

#![allow(clippy::unwrap_used)]

use crate::federation::{IssuerRoutingVerifier, TrustedIssuerVerifier, trusted_issuer_map};
use crate::resource::mem::MemoryResourceStore;
use crate::resource::{ResourceMapping, ResourceService};
use crate::token::{ExchangeError, TokenExchangeService};
use async_trait::async_trait;
use chrono::Utc;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{JwtGenerationError, JwtGenerator, JwtVerificationError, JwtVerifier, TokenClaims};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUER: &str = "https://idp.example.com/realms/example";
const AUDIENCE: &str = "jwtlet-exchange";
const PREFIX: &str = "external-idp:";
const JWKS_PATH: &str = "/certs";

// Test-only keys, generated for these tests.
const ED_KID: &str = "ed-1";
const ED_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBUh6EzLPbOIMFtZUd+1aRHzvpI5Nx9Jw2AP+GCMil8d
-----END PRIVATE KEY-----";
const ED_PUBLIC_X: &str = "4wWBSObMUgPZJYtZsUcAQHU5pkF8rRJ9GtAS_ZKRHRc";

const ED2_KID: &str = "ed-2";
const ED2_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA5vB4uotXrBv65fO959YNGn8/rEGazkVJhepcriNs/B
-----END PRIVATE KEY-----";
const ED2_PUBLIC_X: &str = "U0tgcvcLxmwouYGIKKaoy5zvaUI7qY2QFPhXOdzNQi0";

const RSA_KID: &str = "rsa-1";
const RSA_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDvv7UT3SXe7YWv
lqDjuiqM97yQJiqvX1DMV/XjmSXSdv/zrX3TGaDF4Q1166PSYCx+YMBzBW6gXoJA
Hebe6QsAHRTQyFX9NfIbPlTlwr+/ryYkDR0z+eeN4eFNGlClk3oD/vg9ijOPqwyF
7vRPHhhf4JjS9UtiMlHNJ5GvyxL12b8oTCDAPxqXXfsU2Xzkbbijhe305+LhcAj5
w81Yc+/N0aqVmAJVbMMDMvb0w07eD8W//uwul7D8PL9t/QbVpLlSAmet0k9g+lZ+
7zB7vc5AFYmzeHisNDCDnwpAlDTdDcnB2ngoScx79NP7Zx/77cYWNhV2XDuGbtyi
rMuGZNbHAgMBAAECggEAC9CZE4XbdD/6TZaRDofsdDlP2+lgQyI3BiBI6Cgc8Avt
6HainmuYkQfaikwhgkrmW8Ktg+g+9RI96FD7lqf0uH22ZTo/hT9KU24KmwQHlQ0E
Rn81nYvG4ybAMUoxspHbpSTEhlaFh01OTFoOmh4z5KMEhP488nWOXcYsbMsHf9ax
z1KTJO9GuwAX/4AQC7VEx3jUWlYOc8hAr+tLtiOVxUqkxAbESsMmDS8RuqvBAdY+
J4BzCQsvg6QtUHMMt5Rz8/bj8APiP/CsaWv50MVOjBJyhgbRHIU5QFOgubbLQmnM
YZmPoZklGYoQpautJ8iNeQl6e1hpCRJW9EybWJ/K6QKBgQD6QtV+2NE8Its49INa
BiLt5B0Dw5pQ1fJsYgutr2A+Is53iIA1mbxd1eMahInqp/6JmuQe5sxQRKCHKe5u
zY9zkM40gvSycVBlRFY4dZmG/4CDzpO4gtHw0jvDP8Tk1s1XcdKIH1mk0yhS+mtQ
wmF6ksm2MkcEfE0S0ibCfLBIMwKBgQD1Pyk7jwqn0csZ4Otm7CN9nelkHZzg+rW4
evlIUMCGjrwe1ph5hAKOGrOVYnJUT7P3jElXPfKzsfQ76kzNxrqNCKkfrPr5FSmO
xicZTxvZ3N3z3QTyoHdgurKk4Pu6xzR3pQjDytahChIOuXX4idBdCX2wqKcIXfb7
rK18D0uzHQKBgE0NWtJtSy6qxLhqgC6tiP+Zpl1MUizlUniQT2wwfP9klBE1k9Ps
+5QgkIXPnO8Evlf7upTRFsL3/jzfaivvWmWIhhSg5VozjT9ApRNJEfYAoL70UYMT
tDPjZscc0TBr+lkcEGgczuryoI270GLTFlQ48aYJINh+tPRAg/KJlXUFAoGBAJkx
zSXhInzWNhKCR0nRdBIB1EqvnNGEioMkfhdIKhtjieuRjUlKxvXRhCBqkJRN/VND
FIUkszjAjpnmr/dSjjGPGWYp/dQd/gmribzrh7A9oX+1rmOJDUklFnab+2MfEI00
UBdN22hZDBKakzCflcKoLRVvJHe7io6HvQ7j1xuZAoGBAMy7djZnThUT5sljnJnW
7Ra1dXL+Ew2KWgTV9D7At5dif0O9l1P2Hqrr4ddW36TLT53nVpAlZEqWw60Zs5ab
kTqBn2drm1W1EFpYPvoqbTuPfihcZK0lXZSf3TlFaV6p1w8ZtpVm/OEaB35E3+qk
fyX/hfBs3s7zqjPHqH05Cqfi
-----END PRIVATE KEY-----";
const RSA_PUBLIC_N: &str = "77-1E90l3u2Fr5ag47oqjPe8kCYqr19QzFf145kl0nb_86190xmgxeENdeuj0mAsfmDAcwVuoF6CQB3m3ukLAB0U0MhV_TXyGz5U5cK_v68mJA0dM_nnjeHhTRpQpZN6A_74PYozj6sMhe70Tx4YX-CY0vVLYjJRzSeRr8sS9dm_KEwgwD8al137FNl85G24o4Xt9Ofi4XAI-cPNWHPvzdGqlZgCVWzDAzL29MNO3g_Fv_7sLpew_Dy_bf0G1aS5UgJnrdJPYPpWfu8we73OQBWJs3h4rDQwg58KQJQ03Q3Jwdp4KEnMe_TT-2cf--3GFjYVdlw7hm7coqzLhmTWxw";

fn ed_jwk() -> Value {
    json!({"kty": "OKP", "crv": "Ed25519", "kid": ED_KID, "use": "sig", "x": ED_PUBLIC_X})
}

fn ed2_jwk() -> Value {
    json!({"kty": "OKP", "crv": "Ed25519", "kid": ED2_KID, "use": "sig", "x": ED2_PUBLIC_X})
}

fn rsa_jwk() -> Value {
    json!({"kty": "RSA", "kid": RSA_KID, "use": "sig", "alg": "RS256", "n": RSA_PUBLIC_N, "e": "AQAB"})
}

fn claims() -> Value {
    let now = Utc::now().timestamp();
    json!({"iss": ISSUER, "aud": AUDIENCE, "sub": "client-1", "iat": now, "exp": now + 300})
}

fn sign_ed(kid: &str, private: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_string());
    encode(&header, claims, &EncodingKey::from_ed_pem(private.as_bytes()).unwrap()).unwrap()
}

fn sign(claims: &Value) -> String {
    sign_ed(ED_KID, ED_PRIVATE, claims)
}

fn sign_rsa(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(RSA_KID.to_string());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE.as_bytes()).unwrap(),
    )
    .unwrap()
}

async fn jwks_server(keys: Vec<Value>, expected_fetches: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": keys })))
        .expect(expected_fetches)
        .mount(&server)
        .await;
    server
}

fn verifier(server: &MockServer) -> TrustedIssuerVerifier {
    TrustedIssuerVerifier::builder()
        .issuer(ISSUER)
        .jwks_url(format!("{}{JWKS_PATH}", server.uri()))
        .subject_prefix(PREFIX)
        .build()
}

fn assert_failed(result: Result<TokenClaims, JwtVerificationError>) {
    assert!(result.is_err(), "expected verification to fail, got {result:?}");
}

#[tokio::test]
async fn accepts_token_and_prefixes_subject() {
    let server = jwks_server(vec![ed_jwk()], 1).await;

    let claims = verifier(&server)
        .verify_token(AUDIENCE, &sign(&claims()))
        .await
        .unwrap();

    assert_eq!(claims.sub, "external-idp:client-1");
    assert_eq!(claims.iss, ISSUER);
    assert_eq!(claims.aud, AUDIENCE);
    assert!(
        claims.custom.is_empty(),
        "no claim of the external token may be passed on"
    );
}

#[tokio::test]
async fn accepts_rs256_token_with_audience_list_and_custom_subject_claim() {
    // Shape of a Keycloak client-credentials token: `aud` is a list and the client is in `azp`.
    let server = jwks_server(vec![rsa_jwk()], 1).await;
    let mut c = claims();
    c["aud"] = json!(["account", AUDIENCE]);
    c["sub"] = json!("5f0c1d7e-uuid-of-service-account-user");
    c["azp"] = json!("my-client");
    let v = TrustedIssuerVerifier::builder()
        .issuer(ISSUER)
        .jwks_url(format!("{}{JWKS_PATH}", server.uri()))
        .subject_prefix(PREFIX)
        .subject_claim("azp")
        .build();

    let claims = v.verify_token(AUDIENCE, &sign_rsa(&c)).await.unwrap();

    assert_eq!(claims.sub, "external-idp:my-client");
}

#[tokio::test]
async fn rejects_other_issuer() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let mut c = claims();
    c["iss"] = json!("https://evil.example.com");

    assert_failed(verifier(&server).verify_token(AUDIENCE, &sign(&c)).await);
}

#[tokio::test]
async fn rejects_missing_issuer() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let mut c = claims();
    c.as_object_mut().unwrap().remove("iss");

    assert_failed(verifier(&server).verify_token(AUDIENCE, &sign(&c)).await);
}

#[tokio::test]
async fn rejects_other_audience() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let mut c = claims();
    c["aud"] = json!("some-other-service");

    assert_failed(verifier(&server).verify_token(AUDIENCE, &sign(&c)).await);
}

#[tokio::test]
async fn rejects_expired_token() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let mut c = claims();
    c["exp"] = json!(Utc::now().timestamp() - 3600);

    let result = verifier(&server).verify_token(AUDIENCE, &sign(&c)).await;

    assert!(matches!(result, Err(JwtVerificationError::TokenExpired)), "{result:?}");
}

#[tokio::test]
async fn rejects_token_without_expiry() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let mut c = claims();
    c.as_object_mut().unwrap().remove("exp");

    assert_failed(verifier(&server).verify_token(AUDIENCE, &sign(&c)).await);
}

#[tokio::test]
async fn rejects_token_not_yet_valid() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let mut c = claims();
    c["nbf"] = json!(Utc::now().timestamp() + 3600);

    let result = verifier(&server).verify_token(AUDIENCE, &sign(&c)).await;

    assert!(
        matches!(result, Err(JwtVerificationError::TokenNotYetValid)),
        "{result:?}"
    );
}

#[tokio::test]
async fn rejects_token_signed_with_another_key_under_a_known_kid() {
    let server = jwks_server(vec![ed_jwk()], 1).await;

    let result = verifier(&server)
        .verify_token(AUDIENCE, &sign_ed(ED_KID, ED2_PRIVATE, &claims()))
        .await;

    assert!(
        matches!(result, Err(JwtVerificationError::InvalidSignature)),
        "{result:?}"
    );
}

#[tokio::test]
async fn rejects_symmetric_algorithm() {
    // Alg confusion: an HMAC token keyed with public material must never be accepted.
    let server = jwks_server(vec![ed_jwk()], 0).await;
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(ED_KID.to_string());
    let token = encode(&header, &claims(), &EncodingKey::from_secret(ED_PUBLIC_X.as_bytes())).unwrap();

    assert_failed(verifier(&server).verify_token(AUDIENCE, &token).await);
}

#[tokio::test]
async fn rejects_token_without_kid() {
    let server = jwks_server(vec![ed_jwk()], 0).await;
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &claims(),
        &EncodingKey::from_ed_pem(ED_PRIVATE.as_bytes()).unwrap(),
    )
    .unwrap();

    assert_failed(verifier(&server).verify_token(AUDIENCE, &token).await);
}

#[tokio::test]
async fn rejects_encryption_key() {
    let mut jwk = ed_jwk();
    jwk["use"] = json!("enc");
    let server = jwks_server(vec![jwk], 1).await;

    assert_failed(verifier(&server).verify_token(AUDIENCE, &sign(&claims())).await);
}

#[tokio::test]
async fn rejects_key_pinned_to_another_algorithm() {
    let mut jwk = ed_jwk();
    jwk["alg"] = json!("ES256");
    let server = jwks_server(vec![jwk], 1).await;

    assert_failed(verifier(&server).verify_token(AUDIENCE, &sign(&claims())).await);
}

#[rstest::rstest]
#[case::missing(None)]
#[case::empty(Some(json!("")))]
#[case::whitespace(Some(json!("app 1")))]
#[case::control(Some(json!("app\n1")))]
#[case::not_a_string(Some(json!(42)))]
#[tokio::test]
async fn rejects_invalid_subject(#[case] subject: Option<Value>) {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let mut c = claims();
    match subject {
        Some(s) => c["sub"] = s,
        None => {
            c.as_object_mut().unwrap().remove("sub");
        }
    }

    assert_failed(verifier(&server).verify_token(AUDIENCE, &sign(&c)).await);
}

#[tokio::test]
async fn caches_the_jwks() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let v = verifier(&server);

    for _ in 0..3 {
        v.verify_token(AUDIENCE, &sign(&claims())).await.unwrap();
    }
}

#[tokio::test]
async fn unknown_kid_does_not_refetch_within_the_refresh_interval() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let v = verifier(&server);
    v.verify_token(AUDIENCE, &sign(&claims())).await.unwrap();

    for _ in 0..3 {
        assert_failed(
            v.verify_token(AUDIENCE, &sign_ed(ED2_KID, ED2_PRIVATE, &claims()))
                .await,
        );
    }
}

#[tokio::test]
async fn picks_up_rotated_keys_once_the_cache_expired() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [ed_jwk()] })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [ed2_jwk()] })))
        .mount(&server)
        .await;
    let v = TrustedIssuerVerifier::builder()
        .issuer(ISSUER)
        .jwks_url(format!("{}{JWKS_PATH}", server.uri()))
        .subject_prefix(PREFIX)
        .jwks_cache_ttl(Duration::ZERO)
        .build();

    v.verify_token(AUDIENCE, &sign(&claims())).await.unwrap();
    v.verify_token(AUDIENCE, &sign_ed(ED2_KID, ED2_PRIVATE, &claims()))
        .await
        .unwrap();
    assert_failed(v.verify_token(AUDIENCE, &sign(&claims())).await);
}

#[tokio::test]
async fn fails_closed_when_the_jwks_cannot_be_fetched() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    assert_failed(verifier(&server).verify_token(AUDIENCE, &sign(&claims())).await);
}

#[tokio::test]
async fn skips_unsupported_jwks_entries() {
    let server = jwks_server(vec![json!({"kty": "unknown", "kid": "x"}), ed_jwk()], 1).await;

    verifier(&server)
        .verify_token(AUDIENCE, &sign(&claims()))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------------------------

/// Stands in for the Kubernetes verifier and counts how often it is asked.
struct CountingVerifier(Arc<AtomicUsize>);

#[async_trait]
impl JwtVerifier for CountingVerifier {
    async fn verify_token(&self, audience: &str, _token: &str) -> Result<TokenClaims, JwtVerificationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(TokenClaims::builder()
            .sub("system:serviceaccount:ns:sa")
            .iss("https://kubernetes.default.svc")
            .aud(audience)
            .exp(0)
            .build())
    }
}

fn router(server: &MockServer) -> (IssuerRoutingVerifier, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let router = IssuerRoutingVerifier::builder()
        .default(Box::new(CountingVerifier(calls.clone())))
        .trusted(trusted_issuer_map([verifier(server)]))
        .build();
    (router, calls)
}

#[tokio::test]
async fn routes_tokens_of_a_trusted_issuer_to_its_verifier() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let (router, default_calls) = router(&server);

    let claims = router.verify_token(AUDIENCE, &sign(&claims())).await.unwrap();

    assert_eq!(claims.sub, "external-idp:client-1");
    assert_eq!(default_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn forged_token_of_a_trusted_issuer_is_rejected_and_not_passed_on() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let (router, default_calls) = router(&server);

    assert_failed(
        router
            .verify_token(AUDIENCE, &sign_ed(ED_KID, ED2_PRIVATE, &claims()))
            .await,
    );
    assert_eq!(default_calls.load(Ordering::SeqCst), 0);
}

#[rstest::rstest]
#[case::other_issuer(sign(&json!({"iss": "https://kubernetes.default.svc", "aud": AUDIENCE, "sub": "x", "exp": 1})))]
#[case::no_issuer(sign(&json!({"aud": AUDIENCE, "sub": "x", "exp": 1})))]
#[case::not_a_jwt("opaque-token".to_string())]
#[tokio::test]
async fn routes_all_other_tokens_to_the_default_verifier(#[case] token: String) {
    let server = jwks_server(vec![ed_jwk()], 0).await;
    let (router, default_calls) = router(&server);

    let claims = router.verify_token(AUDIENCE, &token).await.unwrap();

    assert_eq!(claims.sub, "system:serviceaccount:ns:sa");
    assert_eq!(default_calls.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------------------------
// Token exchange with an external subject token
// ---------------------------------------------------------------------------------------------

struct CapturingGenerator(Arc<std::sync::Mutex<Option<TokenClaims>>>);

#[async_trait]
impl JwtGenerator for CapturingGenerator {
    async fn generate_token(
        &self,
        _participant_context: &ParticipantContext,
        claims: TokenClaims,
    ) -> Result<String, JwtGenerationError> {
        *self.0.lock().unwrap() = Some(claims);
        Ok("issued".to_string())
    }
}

async fn exchange_service(
    server: &MockServer,
    client_identifier: &str,
) -> (TokenExchangeService, Arc<std::sync::Mutex<Option<TokenClaims>>>) {
    let store = Arc::new(MemoryResourceStore::new());
    let resources = ResourceService::builder().store(store).build();
    resources
        .save(
            ResourceMapping::builder()
                .client_identifier(client_identifier.to_string())
                .participant_context("test-context".to_string())
                .scopes(HashSet::from(["read".to_string()]))
                .build(),
        )
        .await
        .unwrap();
    let issued = Arc::new(std::sync::Mutex::new(None));
    let (router, _) = router(server);
    let service = TokenExchangeService::builder()
        .client_audience(AUDIENCE)
        .audience("control-plane")
        .issuer("https://jwtlet.example.com")
        .verifier(Box::new(router))
        .resource_service(resources)
        .generator(Box::new(CapturingGenerator(issued.clone())))
        .build();
    (service, issued)
}

#[tokio::test]
async fn exchange_issues_a_token_for_a_mapping_of_the_prefixed_subject() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let (service, issued) = exchange_service(&server, "external-idp:client-1").await;

    service
        .exchange_token("test-context", vec!["read".to_string()], &sign(&claims()), None)
        .await
        .unwrap();

    let claims = issued.lock().unwrap().take().unwrap();
    assert_eq!(claims.sub, "test-context");
    assert_eq!(claims.iss, "https://jwtlet.example.com");
    assert_eq!(
        claims.custom["act"],
        json!({"sub": "external-idp:client-1", "iss": ISSUER})
    );
}

#[tokio::test]
async fn exchange_ignores_a_mapping_of_the_bare_external_subject() {
    let server = jwks_server(vec![ed_jwk()], 1).await;
    let (service, issued) = exchange_service(&server, "client-1").await;

    let result = service
        .exchange_token("test-context", vec!["read".to_string()], &sign(&claims()), None)
        .await;

    assert!(matches!(result, Err(ExchangeError::Unauthorized)), "{result:?}");
    assert!(issued.lock().unwrap().is_none());
}
