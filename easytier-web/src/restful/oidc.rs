use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use subtle::ConstantTimeEq;

use axum::Router;
use axum::routing::get;
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    Client, ClientId, ClientSecret, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IdTokenFields, IssuerUrl, RedirectUrl, StandardErrorResponse,
    StandardTokenResponse,
};
use serde::{Deserialize, Serialize};

use super::AppStateInner;

const DEFAULT_OIDC_SCOPES: [&str; 2] = ["openid", "profile"];

fn normalize_oidc_scopes(scopes: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = scopes
        .iter()
        .map(|scope| scope.trim().to_string())
        .filter(|scope| !scope.is_empty())
        .collect();

    if normalized.is_empty() {
        normalized = DEFAULT_OIDC_SCOPES
            .iter()
            .map(|scope| scope.to_string())
            .collect();
    }

    if !normalized.iter().any(|scope| scope == "openid") {
        normalized.insert(0, "openid".to_string());
    }

    normalized
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsonAdditionalClaims {
    #[serde(flatten)]
    pub claims: HashMap<String, serde_json::Value>,
}

impl openidconnect::AdditionalClaims for JsonAdditionalClaims {}

pub type AppIdTokenFields = IdTokenFields<
    JsonAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

pub type AppTokenResponse = StandardTokenResponse<AppIdTokenFields, CoreTokenType>;

pub type AppClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
    HasUserInfoUrl = EndpointNotSet,
> = Client<
    JsonAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    AppTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

pub type ConfiguredAppClient = AppClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Convert a dot-path (e.g. `realm_access.roles.0`) to a JSON Pointer (e.g. `/realm_access/roles/0`).
/// Each segment is escaped per RFC 6901: `~` → `~0`, `/` → `~1`.
fn dot_path_to_json_pointer(dot_path: &str) -> String {
    let mut pointer = String::new();
    for segment in dot_path.split('.') {
        pointer.push('/');
        for ch in segment.chars() {
            match ch {
                '~' => pointer.push_str("~0"),
                '/' => pointer.push_str("~1"),
                _ => pointer.push(ch),
            }
        }
    }
    pointer
}

/// Timing-safe string comparison via constant-time equality check.
/// Prevents timing side-channel attacks on CSRF token verification.
fn timing_safe_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn instant_to_rfc3339(expires_at: Instant) -> String {
    let remaining = expires_at.saturating_duration_since(Instant::now());
    let system_time = SystemTime::now()
        .checked_add(remaining)
        .unwrap_or_else(SystemTime::now);
    chrono::DateTime::<chrono::Utc>::from(system_time).to_rfc3339()
}

fn build_frontend_auth_redirect_url(
    frontend_base_url: Option<&str>,
    token: &str,
    expires_at: &str,
) -> String {
    let base = frontend_base_url.unwrap_or("/").trim_end_matches('/');
    let base = if base.is_empty() { "/" } else { base };
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("token", token)
        .append_pair("expires_at", expires_at)
        .finish();

    if base == "/" {
        format!("/#/auth?{query}")
    } else {
        format!("{base}#/auth?{query}")
    }
}

#[derive(Debug, Clone, clap::Args)]
pub struct OidcOptions {
    #[arg(long, help = t!("cli.oidc_issuer_url").to_string())]
    pub oidc_issuer_url: Option<String>,

    #[arg(long, help = t!("cli.oidc_client_id").to_string())]
    pub oidc_client_id: Option<String>,

    #[arg(long, env = "OIDC_CLIENT_SECRET", help = t!("cli.oidc_client_secret").to_string())]
    pub oidc_client_secret: Option<String>,

    #[arg(long, default_value = "preferred_username", help = t!("cli.oidc_username_claim").to_string())]
    pub oidc_username_claim: String,

    #[arg(
        long,
        value_delimiter = ',',
        default_values = DEFAULT_OIDC_SCOPES,
        help = t!("cli.oidc_scopes").to_string()
    )]
    pub oidc_scopes: Vec<String>,

    #[arg(long, help = t!("cli.oidc_redirect_url").to_string())]
    pub oidc_redirect_url: Option<String>,

    #[arg(long, default_value = "false", help = t!("cli.oidc_disable_pkce").to_string())]
    pub oidc_disable_pkce: bool,

    #[arg(long, help = t!("cli.oidc_frontend_base_url").to_string())]
    pub oidc_frontend_base_url: Option<String>,
}

impl OidcOptions {
    pub fn any_param_provided(&self) -> bool {
        self.oidc_issuer_url.is_some()
            || self.oidc_client_id.is_some()
            || self.oidc_client_secret.is_some()
            || self.oidc_redirect_url.is_some()
            || self.oidc_frontend_base_url.is_some()
            || self.oidc_username_claim != "preferred_username"
            || self.oidc_scopes != DEFAULT_OIDC_SCOPES
            || self.oidc_disable_pkce
    }
}

#[derive(Clone)]
pub struct OidcConfig {
    pub enabled: bool,
    pub provider_metadata: Option<Arc<CoreProviderMetadata>>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_url: Option<RedirectUrl>,
    pub username_claim: String,
    pub scopes: Vec<String>,
    pub pkce_enabled: bool,
    pub frontend_base_url: Option<String>,
    pub http_client: Option<reqwest::Client>,
    cached_client: Option<Arc<ConfiguredAppClient>>,
}

impl OidcConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            provider_metadata: None,
            client_id: String::new(),
            client_secret: None,
            redirect_url: None,
            username_claim: "preferred_username".to_string(),
            scopes: DEFAULT_OIDC_SCOPES
                .iter()
                .map(|scope| scope.to_string())
                .collect(),
            pkce_enabled: false,
            frontend_base_url: None,
            http_client: None,
            cached_client: None,
        }
    }

    pub async fn from_params(opts: OidcOptions) -> anyhow::Result<Self> {
        let OidcOptions {
            oidc_issuer_url,
            oidc_client_id,
            oidc_client_secret,
            oidc_username_claim,
            oidc_scopes,
            oidc_redirect_url,
            oidc_disable_pkce,
            oidc_frontend_base_url,
        } = opts;

        if oidc_issuer_url.is_none() || oidc_client_id.is_none() || oidc_redirect_url.is_none() {
            return Err(anyhow::anyhow!(
                "--oidc-issuer-url, --oidc-client-id and --oidc-redirect-url are required when using OIDC authentication"
            ));
        }
        if oidc_username_claim.trim().is_empty() {
            return Err(anyhow::anyhow!("--oidc-username-claim cannot be empty"));
        }
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;

        let issuer_url = oidc_issuer_url.ok_or_else(|| {
            anyhow::anyhow!("--oidc-issuer-url is required when using OIDC authentication")
        })?;

        let provider_metadata =
            CoreProviderMetadata::discover_async(IssuerUrl::new(issuer_url)?, &http_client).await?;

        let client_id = oidc_client_id.ok_or_else(|| {
            anyhow::anyhow!("--oidc-client-id is required when using OIDC authentication")
        })?;

        let redirect_url = oidc_redirect_url
            .ok_or_else(|| anyhow::anyhow!("--oidc-redirect-url is required when using OIDC authentication. The redirect URL must match exactly what is registered with your Identity Provider. Example: --oidc-redirect-url http://your-domain.com:11211/api/v1/auth/oidc/callback"))?;

        let provider_metadata = Arc::new(provider_metadata);
        let redirect_url = RedirectUrl::new(redirect_url)?;
        let client_secret = oidc_client_secret;

        let cached_client = {
            let c = AppClient::from_provider_metadata(
                provider_metadata.as_ref().clone(),
                ClientId::new(client_id.clone()),
                client_secret.as_ref().map(|s| ClientSecret::new(s.clone())),
            )
            .set_redirect_uri(redirect_url.clone());
            Arc::new(c)
        };

        Ok(Self {
            enabled: true,
            provider_metadata: Some(provider_metadata),
            client_id,
            client_secret,
            redirect_url: Some(redirect_url),
            username_claim: oidc_username_claim,
            scopes: normalize_oidc_scopes(&oidc_scopes),
            pkce_enabled: !oidc_disable_pkce,
            frontend_base_url: oidc_frontend_base_url,
            http_client: Some(http_client),
            cached_client: Some(cached_client),
        })
    }

    pub fn client(&self) -> Option<&ConfiguredAppClient> {
        self.cached_client.as_deref()
    }
}

pub fn router() -> Router<AppStateInner> {
    Router::new()
        .route("/api/v1/auth/oidc/config", get(self::route::oidc_config))
        .route("/api/v1/auth/oidc/login", get(self::route::oidc_login))
        .route(
            "/api/v1/auth/oidc/callback",
            get(self::route::oidc_callback),
        )
}

mod route {
    use std::sync::Arc;

    use axum::extract::Query;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Redirect, Response};
    use axum::{Extension, Json};
    use openidconnect::core::CoreAuthenticationFlow;
    use openidconnect::{
        AccessTokenHash, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse,
        PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
    };
    use serde::Deserialize;

    use crate::restful::auth_state::{BearerTokenStore, OidcStateStore};
    use crate::restful::other_error;

    use super::OidcConfig;

    pub async fn oidc_config(Extension(oidc): Extension<OidcConfig>) -> Json<serde_json::Value> {
        Json(serde_json::json!({ "enabled": oidc.enabled }))
    }

    pub async fn oidc_login(
        Extension(oidc): Extension<OidcConfig>,
        Extension(oidc_state_store): Extension<Arc<OidcStateStore>>,
    ) -> Response {
        if !oidc.enabled {
            return (
                StatusCode::BAD_REQUEST,
                Json(other_error("OIDC is not enabled")),
            )
                .into_response();
        }

        let client = match oidc.client() {
            Some(c) => c,
            None => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(other_error("OIDC client not initialized")),
                )
                    .into_response();
            }
        };

        let scopes = oidc.scopes.clone();
        let pkce_enabled = oidc.pkce_enabled;

        let (pkce_challenge, pkce_verifier) = if pkce_enabled {
            let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
            (Some(challenge), Some(verifier))
        } else {
            (None, None)
        };

        let mut auth_request = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );

        for scope in &scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        if let Some(challenge) = pkce_challenge {
            auth_request = auth_request.set_pkce_challenge(challenge);
        }

        let (auth_url, csrf_token, nonce) = auth_request.url();

        oidc_state_store.insert(
            csrf_token.secret().clone(),
            nonce.secret().clone(),
            pkce_verifier.map(|verifier| verifier.secret().clone()),
            pkce_enabled,
        );

        Redirect::temporary(auth_url.as_str()).into_response()
    }

    #[derive(Deserialize)]
    pub struct CallbackParams {
        pub(crate) code: Option<String>,
        pub(crate) state: Option<String>,
        pub(crate) error: Option<String>,
        pub(crate) error_description: Option<String>,
    }

    impl CallbackParams {
        #[cfg(test)]
        pub(crate) fn test_new(
            code: Option<String>,
            state: Option<String>,
            error: Option<String>,
            error_description: Option<String>,
        ) -> Self {
            Self {
                code,
                state,
                error,
                error_description,
            }
        }
    }

    pub async fn oidc_callback(
        Extension(oidc): Extension<OidcConfig>,
        Extension(oidc_state_store): Extension<Arc<OidcStateStore>>,
        Extension(token_store): Extension<Arc<BearerTokenStore>>,
        Query(params): Query<CallbackParams>,
    ) -> Response {
        if !oidc.enabled {
            return (
                StatusCode::BAD_REQUEST,
                Json(other_error("OIDC is not enabled")),
            )
                .into_response();
        }

        if let Some(ref error) = params.error {
            tracing::error!(
                "OIDC provider returned error: {}, description: {:?}",
                error,
                params.error_description
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(other_error(
                    "Authentication failed at the identity provider",
                )),
            )
                .into_response();
        }

        let code = match params.code {
            Some(ref c) => c.clone(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(other_error("Missing authorization code")),
                )
                    .into_response();
            }
        };

        let callback_state = match params.state {
            Some(ref s) => s.clone(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(other_error("Missing state parameter in callback")),
                )
                    .into_response();
            }
        };

        let stored_state = match oidc_state_store.consume(&callback_state) {
            Some(state) => {
                oidc_state_store.remove(&callback_state);
                state
            }
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(other_error(
                        "Missing, expired, or already consumed OIDC state",
                    )),
                )
                    .into_response();
            }
        };

        if !super::timing_safe_eq(&stored_state.state, &callback_state) {
            return (
                StatusCode::BAD_REQUEST,
                Json(other_error("CSRF state mismatch")),
            )
                .into_response();
        }

        if stored_state.nonce.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(other_error("Missing nonce in OIDC state store")),
            )
                .into_response();
        }

        let stored_pkce_verifier = stored_state.pkce_verifier.clone();
        if stored_state.pkce_used
            && stored_pkce_verifier
                .as_deref()
                .map(|verifier| verifier.is_empty())
                .unwrap_or(true)
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(other_error(
                    "PKCE was enabled but verifier is missing from state store",
                )),
            )
                .into_response();
        }

        let client = match oidc.client() {
            Some(c) => c,
            None => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(other_error("OIDC client not initialized")),
                )
                    .into_response();
            }
        };

        let http_client = match oidc.http_client.as_ref() {
            Some(c) => c,
            None => {
                tracing::error!("HTTP client not initialized in OIDC config");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(other_error("OIDC internal error")),
                )
                    .into_response();
            }
        };

        let mut token_request = match client.exchange_code(AuthorizationCode::new(code)) {
            Ok(req) => req,
            Err(e) => {
                tracing::error!("Failed to create token request: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(other_error("Failed to create token exchange request")),
                )
                    .into_response();
            }
        };

        if let Some(stored_pkce_verifier) = stored_pkce_verifier {
            token_request =
                token_request.set_pkce_verifier(PkceCodeVerifier::new(stored_pkce_verifier));
        }

        let token_response = match token_request.request_async(http_client).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("Failed to exchange code for token: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(other_error("Token exchange failed")),
                )
                    .into_response();
            }
        };

        let id_token = match token_response.id_token() {
            Some(t) => t,
            None => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(other_error("No ID token in response")),
                )
                    .into_response();
            }
        };

        let claims =
            match id_token.claims(&client.id_token_verifier(), &Nonce::new(stored_state.nonce)) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Failed to verify ID token: {:?}", e);
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(other_error("ID token verification failed")),
                    )
                        .into_response();
                }
            };

        if let Some(expected_at_hash) = claims.access_token_hash() {
            let id_token_verifier = client.id_token_verifier();
            let (Ok(signing_alg), Ok(signing_key)) = (
                id_token.signing_alg(),
                id_token.signing_key(&id_token_verifier),
            ) else {
                tracing::error!("Failed to get signing algorithm or key for at_hash verification");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(other_error("Failed to determine token signing algorithm")),
                )
                    .into_response();
            };

            let actual_at_hash = match AccessTokenHash::from_token(
                token_response.access_token(),
                signing_alg,
                signing_key,
            ) {
                Ok(hash) => hash,
                Err(e) => {
                    tracing::error!("Failed to compute access token hash: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(other_error("Failed to verify access token hash")),
                    )
                        .into_response();
                }
            };

            if actual_at_hash != *expected_at_hash {
                tracing::error!("Access token hash mismatch");
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(other_error("Access token hash mismatch")),
                )
                    .into_response();
            }
        }

        let claims_json = match serde_json::to_value(claims) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Failed to serialize claims: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(other_error("Failed to process ID token claims")),
                )
                    .into_response();
            }
        };

        let pointer = super::dot_path_to_json_pointer(&oidc.username_claim);
        let username: Option<String> = claims_json
            .pointer(&pointer)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let username = match username {
            Some(u) if !u.is_empty() => u,
            _ => {
                tracing::error!(
                    "Could not extract username from claim '{}' in token",
                    oidc.username_claim
                );
                return (
                    StatusCode::BAD_REQUEST,
                    Json(other_error("Could not extract username from token claims")),
                )
                    .into_response();
            }
        };

        let user = match token_store
            .backend()
            .find_or_create_oidc_user(&username)
            .await
        {
            Ok(u) => u,
            Err(e) => {
                tracing::error!("Failed to find or create OIDC user '{}': {:?}", username, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(other_error("Failed to provision user account")),
                )
                    .into_response();
            }
        };

        let token = token_store.issue_token(user.id());
        let expires_at = match token_store.get(&token) {
            Some(context) => super::instant_to_rfc3339(context.expires_at),
            None => {
                tracing::error!("Failed to resolve freshly-issued OIDC bearer token");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(other_error("Failed to issue bearer token")),
                )
                    .into_response();
            }
        };

        let redirect_url = super::build_frontend_auth_redirect_url(
            oidc.frontend_base_url.as_deref(),
            &token,
            &expires_at,
        );
        Redirect::temporary(&redirect_url).into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{
        Extension, Json, Router,
        body::to_bytes,
        extract::{Form, Query, State},
        http::{StatusCode, header},
        response::{IntoResponse, Response},
        routing::post,
    };
    use chrono::{Duration as ChronoDuration, Utc};
    use openidconnect::core::{
        CoreGenderClaim, CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm, CoreResponseType, CoreRsaPrivateSigningKey,
        CoreSubjectIdentifierType, CoreTokenType,
    };
    use openidconnect::{
        AccessToken, Audience, AuthUrl, ClientId, ClientSecret, EmptyExtraTokenFields,
        EndUserUsername, IdToken, IdTokenClaims, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, Nonce,
        PrivateSigningKey, StandardClaims, SubjectIdentifier, TokenUrl,
    };

    use crate::restful::auth_state::{BearerTokenStore, OidcStateStore};
    use crate::restful::users::Backend;

    use super::*;

    const TEST_RSA_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
         MIIEowIBAAKCAQEAn4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8/KuKPEHLd4\n\
         rHVTeT+O+XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz/AJmSCpMaJMRBSFKrKb2wqVwG\n\
         U/NsYOYL+QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj+oBHqFEHYpP\n\
         e7Tpe+OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzw\n\
         OHrtIQbS0FVbb9k3+tVTU4fg/3L/vniUFAKwuCLqKnS2BYwdq/mzSnbLY7h/qixo\n\
         R7jig3//kRhuaxwUkRz5iaiQkqgc5gHdrNP5zwIDAQABAoIBAG1lAvQfhBUSKPJK\n\
         Rn4dGbshj7zDSr2FjbQf4pIh/ZNtHk/jtavyO/HomZKV8V0NFExLNi7DUUvvLiW7\n\
         0PgNYq5MDEjJCtSd10xoHa4QpLvYEZXWO7DQPwCmRofkOutf+NqyDS0QnvFvp2d+\n\
         Lov6jn5C5yvUFgw6qWiLAPmzMFlkgxbtjFAWMJB0zBMy2BqjntOJ6KnqtYRMQUxw\n\
         TgXZDF4rhYVKtQVOpfg6hIlsaoPNrF7dofizJ099OOgDmCaEYqM++bUlEHxgrIVk\n\
         wZz+bg43dfJCocr9O5YX0iXaz3TOT5cpdtYbBX+C/5hwrqBWru4HbD3xz8cY1TnD\n\
         qQa0M8ECgYEA3Slxg/DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex/fp7AZ/9\n\
         nRaO7HX/+SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr/WCsmGpeNqQn\n\
         ev1T7IyEsnh8UMt+n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0kCgYEAuKE2\n\
         dh+cTf6ERF4k4e/jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR/cu0Dm1MZwW\n\
         mtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoB\n\
         vyY898EXvRD+hdqRxHlSqAZ192zB3pVFJ0s7pFcCgYAHw9W9eS8muPYv4ZhDu/fL\n\
         2vorDmD1JqFcHCxZTOnX1NWWAj5hXzmrU0hvWvFC0P4ixddHf5Nqd6+5E9G3k4E5\n\
         2IwZCnylu3bqCWNh8pT8T3Gf5FQsfPT5530T2BcsoPhUaeCnP499D+rb2mTnFYeg\n\
         mnTT1B/Ue8KGLFFfn16GKQKBgAiw5gxnbocpXPaO6/OKxFFZ+6c0OjxfN2PogWce\n\
         TU/k6ZzmShdaRKwDFXisxRJeNQ5Rx6qgS0jNFtbDhW8E8WFmQ5urCOqIOYk28EBi\n\
         At4JySm4v+5P7yYBh8B8YD2l9j57z/s8hJAxEbn/q8uHP2ddQqvQKgtsni+pHSk9\n\
         XGBfAoGBANz4qr10DdM8DHhPrAb2YItvPVz/VwkBd1Vqj8zCpyIEKe/07oKOvjWQ\n\
         SgkLDH9x2hBgY01SbP43CvPk0V72invu2TGkI/FXwXWJLLG7tDSgw4YyfhrYrHmg\n\
         1Vre3XB9HH8MYBVB6UIexaAq4xSeoemRKTBesZro7OKjKT8/GmiO\n\
         -----END RSA PRIVATE KEY-----";

    #[derive(Clone)]
    struct MockOidcProviderState {
        issuer: String,
        client_id: String,
        client_secret: String,
        expected_code: String,
        expected_pkce_verifier: Option<String>,
        access_token: String,
        username: String,
        nonce: String,
        token_requests: Arc<AtomicUsize>,
    }

    #[derive(Deserialize)]
    struct MockTokenRequest {
        grant_type: String,
        code: String,
        redirect_uri: Option<String>,
        code_verifier: Option<String>,
    }

    async fn make_backend() -> Backend {
        Backend::new(crate::db::Db::memory_db().await)
    }

    async fn mock_token_endpoint(
        State(state): State<MockOidcProviderState>,
        Form(form): Form<MockTokenRequest>,
    ) -> Response {
        state.token_requests.fetch_add(1, Ordering::SeqCst);

        assert_eq!(form.grant_type, "authorization_code");
        assert_eq!(form.code, state.expected_code);
        assert!(form.redirect_uri.is_some());
        assert_eq!(form.code_verifier, state.expected_pkce_verifier);

        let access_token = AccessToken::new(state.access_token.clone());
        let claims = IdTokenClaims::<JsonAdditionalClaims, CoreGenderClaim>::new(
            IssuerUrl::new(state.issuer.clone()).unwrap(),
            vec![Audience::new(state.client_id.clone())],
            Utc::now() + ChronoDuration::minutes(5),
            Utc::now(),
            StandardClaims::new(SubjectIdentifier::new("oidc-user-subject".to_string()))
                .set_preferred_username(Some(EndUserUsername::new(state.username.clone()))),
            JsonAdditionalClaims::default(),
        )
        .set_nonce(Some(Nonce::new(state.nonce.clone())));
        let signing_key = CoreRsaPrivateSigningKey::from_pem(
            TEST_RSA_PRIVATE_KEY,
            Some(JsonWebKeyId::new("test-key".to_string())),
        )
        .unwrap();
        let id_token = IdToken::<
            JsonAdditionalClaims,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        >::new(
            claims,
            &signing_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            Some(&access_token),
            None,
        )
        .unwrap();
        let mut token_response = AppTokenResponse::new(
            access_token,
            CoreTokenType::Bearer,
            AppIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
        );
        token_response.set_expires_in(Some(&std::time::Duration::from_secs(300)));

        Json(token_response).into_response()
    }

    async fn spawn_mock_oidc_provider(
        mut state: MockOidcProviderState,
    ) -> (MockOidcProviderState, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        state.issuer = format!("http://{addr}");
        let app = Router::new()
            .route("/token", post(mock_token_endpoint))
            .with_state(state.clone());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (state, handle)
    }

    fn make_test_oidc_config(
        issuer: String,
        client_id: String,
        client_secret: String,
        token_endpoint: String,
        frontend_base_url: Option<String>,
    ) -> OidcConfig {
        let provider_metadata = Arc::new(
            CoreProviderMetadata::new(
                IssuerUrl::new(issuer).unwrap(),
                AuthUrl::new("https://provider.example/authorize".to_string()).unwrap(),
                JsonWebKeySetUrl::new("https://provider.example/jwks".to_string()).unwrap(),
                vec![openidconnect::ResponseTypes::new(vec![
                    CoreResponseType::Code,
                ])],
                vec![CoreSubjectIdentifierType::Public],
                vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
                openidconnect::EmptyAdditionalProviderMetadata {},
            )
            .set_jwks(CoreJsonWebKeySet::new(vec![
                CoreRsaPrivateSigningKey::from_pem(
                    TEST_RSA_PRIVATE_KEY,
                    Some(JsonWebKeyId::new("test-key".to_string())),
                )
                .unwrap()
                .as_verification_key(),
            ]))
            .set_token_endpoint(Some(TokenUrl::new(token_endpoint).unwrap())),
        );
        let redirect_url = openidconnect::RedirectUrl::new(
            "http://localhost/api/v1/auth/oidc/callback".to_string(),
        )
        .unwrap();
        let client = Arc::new(
            AppClient::from_provider_metadata(
                provider_metadata.as_ref().clone(),
                ClientId::new(client_id.clone()),
                Some(ClientSecret::new(client_secret.clone())),
            )
            .set_redirect_uri(redirect_url.clone()),
        );

        OidcConfig {
            enabled: true,
            provider_metadata: Some(provider_metadata),
            client_id,
            client_secret: Some(client_secret),
            redirect_url: Some(redirect_url),
            username_claim: "preferred_username".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            pkce_enabled: true,
            frontend_base_url,
            http_client: Some(reqwest::Client::new()),
            cached_client: Some(client),
        }
    }

    fn parse_auth_redirect(response: &Response) -> HashMap<String, String> {
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        let url = url::Url::parse(location).unwrap();
        let fragment = url.fragment().unwrap();
        assert!(
            fragment.starts_with("/auth?"),
            "unexpected fragment: {fragment}"
        );
        url::form_urlencoded::parse(fragment.trim_start_matches("/auth?").as_bytes())
            .into_owned()
            .collect()
    }

    async fn response_body_json(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn test_dot_path_to_json_pointer() {
        use serde_json::json;

        let cases = vec![
            (
                "realm_access.roles.0",
                "/realm_access/roles/0",
                json!({ "realm_access": { "roles": ["admin", "user"] } }),
                "admin",
            ),
            (
                "preferred_username",
                "/preferred_username",
                json!({ "preferred_username": "bob" }),
                "bob",
            ),
            ("a~b.c", "/a~0b/c", json!({ "a~b": { "c": "v" } }), "v"),
            ("a/b.c", "/a~1b/c", json!({ "a/b": { "c": "w" } }), "w"),
            ("~/.x", "/~0~1/x", json!({ "~/": { "x": "z" } }), "z"),
            ("a..b", "/a//b", json!({ "a": { "": { "b": "x" } } }), "x"),
            ("", "/", json!({ "": "root" }), "root"),
        ];

        for (path, expected_ptr, json_val, expected_val) in cases {
            let ptr = dot_path_to_json_pointer(path);
            assert_eq!(ptr, expected_ptr, "Pointer mismatch for path: {}", path);
            assert_eq!(
                json_val.pointer(&ptr).and_then(|v| v.as_str()),
                Some(expected_val),
                "Value extraction failed for path: {}, pointer: {}",
                path,
                ptr
            );
        }
    }

    #[tokio::test]
    async fn oidc_bearer_callback_issues_token() {
        let backend = make_backend().await;
        let token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend.clone(),
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let oidc_state_store = Arc::new(OidcStateStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let token_requests = Arc::new(AtomicUsize::new(0));
        let provider_state = MockOidcProviderState {
            issuer: String::new(),
            client_id: "oidc-client".to_string(),
            client_secret: "oidc-secret".to_string(),
            expected_code: "valid-code".to_string(),
            expected_pkce_verifier: Some("pkce-verifier".to_string()),
            access_token: "provider-access-token".to_string(),
            username: "oidc-bearer-user".to_string(),
            nonce: "oidc-nonce".to_string(),
            token_requests: token_requests.clone(),
        };
        let (server_state, server) = spawn_mock_oidc_provider(provider_state).await;
        let oidc = make_test_oidc_config(
            server_state.issuer.clone(),
            server_state.client_id.clone(),
            server_state.client_secret.clone(),
            format!("{}/token", server_state.issuer),
            Some("https://frontend.example/app/".to_string()),
        );

        oidc_state_store.insert(
            "state-success",
            server_state.nonce.clone(),
            server_state.expected_pkce_verifier.clone(),
            true,
        );

        let response = route::oidc_callback(
            Extension(oidc),
            Extension(oidc_state_store.clone()),
            Extension(token_store.clone()),
            Query(route::CallbackParams::test_new(
                Some(server_state.expected_code.clone()),
                Some("state-success".to_string()),
                None,
                None,
            )),
        )
        .await;

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(token_requests.load(Ordering::SeqCst), 1);
        assert!(oidc_state_store.get("state-success").is_none());

        let params = parse_auth_redirect(&response);
        let token = params.get("token").unwrap();
        let expires_at = params.get("expires_at").unwrap();
        let token_context = token_store.get(token).expect("token should be stored");
        let user = backend
            .find_user_by_id(token_context.user_id)
            .await
            .unwrap()
            .expect("oidc user should exist");

        assert_eq!(user.db_user.username, server_state.username);
        assert!(chrono::DateTime::parse_from_rfc3339(expires_at).is_ok());
        assert!(expires_at.contains('T'));

        server.abort();
    }

    #[tokio::test]
    async fn oidc_bearer_rejects_expired_or_replayed_state() {
        let backend = make_backend().await;
        let token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let oidc_state_store = Arc::new(OidcStateStore::with_ttl_and_cleanup_interval(
            Duration::from_millis(20),
            Duration::from_millis(10),
        ));
        let token_requests = Arc::new(AtomicUsize::new(0));
        let provider_state = MockOidcProviderState {
            issuer: String::new(),
            client_id: "oidc-client".to_string(),
            client_secret: "oidc-secret".to_string(),
            expected_code: "valid-code".to_string(),
            expected_pkce_verifier: Some("pkce-verifier".to_string()),
            access_token: "provider-access-token".to_string(),
            username: "oidc-bearer-user".to_string(),
            nonce: "oidc-nonce".to_string(),
            token_requests: token_requests.clone(),
        };
        let (provider_state, server) = spawn_mock_oidc_provider(provider_state).await;
        let oidc = make_test_oidc_config(
            provider_state.issuer.clone(),
            provider_state.client_id.clone(),
            provider_state.client_secret.clone(),
            format!("{}/token", provider_state.issuer),
            Some("https://frontend.example/app".to_string()),
        );

        oidc_state_store.insert(
            "state-expired",
            provider_state.nonce.clone(),
            provider_state.expected_pkce_verifier.clone(),
            true,
        );
        tokio::time::sleep(Duration::from_millis(40)).await;

        let expired_response = route::oidc_callback(
            Extension(oidc.clone()),
            Extension(oidc_state_store.clone()),
            Extension(token_store.clone()),
            Query(route::CallbackParams::test_new(
                Some(provider_state.expected_code.clone()),
                Some("state-expired".to_string()),
                None,
                None,
            )),
        )
        .await;
        assert_eq!(expired_response.status(), StatusCode::BAD_REQUEST);
        let expired_body = response_body_json(expired_response).await;
        assert!(
            expired_body["message"]
                .as_str()
                .unwrap()
                .contains("Missing, expired, or already consumed OIDC state")
        );
        assert_eq!(token_requests.load(Ordering::SeqCst), 0);

        oidc_state_store.insert(
            "state-replay",
            provider_state.nonce.clone(),
            provider_state.expected_pkce_verifier.clone(),
            true,
        );
        let first_response = route::oidc_callback(
            Extension(oidc.clone()),
            Extension(oidc_state_store.clone()),
            Extension(token_store.clone()),
            Query(route::CallbackParams::test_new(
                Some(provider_state.expected_code.clone()),
                Some("state-replay".to_string()),
                None,
                None,
            )),
        )
        .await;
        assert_eq!(first_response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(token_requests.load(Ordering::SeqCst), 1);

        let replay_response = route::oidc_callback(
            Extension(oidc),
            Extension(oidc_state_store),
            Extension(token_store),
            Query(route::CallbackParams::test_new(
                Some(provider_state.expected_code),
                Some("state-replay".to_string()),
                None,
                None,
            )),
        )
        .await;
        assert_eq!(replay_response.status(), StatusCode::BAD_REQUEST);
        let replay_body = response_body_json(replay_response).await;
        assert!(
            replay_body["message"]
                .as_str()
                .unwrap()
                .contains("Missing, expired, or already consumed OIDC state")
        );
        assert_eq!(token_requests.load(Ordering::SeqCst), 1);

        server.abort();
    }

    #[tokio::test]
    async fn oidc_bearer_restart_invalidates_pending_login_state() {
        let backend = make_backend().await;
        let token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let original_store = Arc::new(OidcStateStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let token_requests = Arc::new(AtomicUsize::new(0));
        let provider_state = MockOidcProviderState {
            issuer: String::new(),
            client_id: "oidc-client".to_string(),
            client_secret: "oidc-secret".to_string(),
            expected_code: "valid-code".to_string(),
            expected_pkce_verifier: Some("pkce-verifier".to_string()),
            access_token: "provider-access-token".to_string(),
            username: "oidc-bearer-user".to_string(),
            nonce: "oidc-nonce".to_string(),
            token_requests: token_requests.clone(),
        };
        let (provider_state, server) = spawn_mock_oidc_provider(provider_state).await;
        let oidc = make_test_oidc_config(
            provider_state.issuer.clone(),
            provider_state.client_id.clone(),
            provider_state.client_secret.clone(),
            format!("{}/token", provider_state.issuer),
            Some("https://frontend.example/app".to_string()),
        );

        original_store.insert(
            "state-restart",
            provider_state.nonce.clone(),
            provider_state.expected_pkce_verifier.clone(),
            true,
        );
        drop(original_store);
        let restarted_store = Arc::new(OidcStateStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));

        let response = route::oidc_callback(
            Extension(oidc),
            Extension(restarted_store),
            Extension(token_store),
            Query(route::CallbackParams::test_new(
                Some(provider_state.expected_code),
                Some("state-restart".to_string()),
                None,
                None,
            )),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_body_json(response).await;
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("Missing, expired, or already consumed OIDC state")
        );
        assert_eq!(token_requests.load(Ordering::SeqCst), 0);

        server.abort();
    }
}
