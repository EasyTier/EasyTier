use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use subtle::ConstantTimeEq;

use axum::routing::get;
use axum::Router;
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
            return Err(anyhow::anyhow!("--oidc-issuer-url, --oidc-client-id and --oidc-redirect-url are required when using OIDC authentication"));
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

    use crate::restful::other_error;
    use crate::restful::users::AuthSession;

    use super::OidcConfig;

    pub async fn oidc_config(Extension(oidc): Extension<OidcConfig>) -> Json<serde_json::Value> {
        Json(serde_json::json!({ "enabled": oidc.enabled }))
    }

    pub async fn oidc_login(
        Extension(oidc): Extension<OidcConfig>,
        session: tower_sessions::Session,
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

        if let Err(e) = session
            .insert("oidc_csrf_token", csrf_token.secret().clone())
            .await
        {
            tracing::error!("Failed to store csrf_token in session: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(other_error("Session error")),
            )
                .into_response();
        }
        if let Err(e) = session.insert("oidc_nonce", nonce.secret().clone()).await {
            tracing::error!("Failed to store nonce in session: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(other_error("Session error")),
            )
                .into_response();
        }
        if let Some(verifier) = pkce_verifier {
            if let Err(e) = session
                .insert("oidc_pkce_verifier", verifier.secret().clone())
                .await
            {
                tracing::error!("Failed to store pkce_verifier in session: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(other_error("Session error")),
                )
                    .into_response();
            }
        }
        if let Err(e) = session.insert("oidc_pkce_used", pkce_enabled).await {
            tracing::error!("Failed to store pkce_used in session: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(other_error("Session error")),
            )
                .into_response();
        }

        Redirect::temporary(auth_url.as_str()).into_response()
    }

    #[derive(Deserialize)]
    pub struct CallbackParams {
        code: Option<String>,
        state: Option<String>,
        error: Option<String>,
        error_description: Option<String>,
    }

    async fn cleanup_oidc_session(session: &tower_sessions::Session) {
        let _ = session.remove::<String>("oidc_csrf_token").await;
        let _ = session.remove::<String>("oidc_nonce").await;
        let _ = session.remove::<String>("oidc_pkce_verifier").await;
        let _ = session.remove::<bool>("oidc_pkce_used").await;
    }

    pub async fn oidc_callback(
        Extension(oidc): Extension<OidcConfig>,
        Query(params): Query<CallbackParams>,
        session: tower_sessions::Session,
        mut auth_session: AuthSession,
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
                StatusCode::BAD_REQUEST,
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

        let stored_csrf: String = match session.get("oidc_csrf_token").await {
            Ok(Some(v)) => v,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(other_error("Missing or invalid CSRF token in session")),
                )
                    .into_response();
            }
        };
        if !super::timing_safe_eq(&stored_csrf, &callback_state) {
            return (
                StatusCode::BAD_REQUEST,
                Json(other_error("CSRF state mismatch")),
            )
                .into_response();
        }

        let stored_nonce: String = match session.get("oidc_nonce").await {
            Ok(Some(v)) => v,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(other_error("Missing nonce in session")),
                )
                    .into_response();
            }
        };

        let stored_pkce_verifier: Option<String> =
            session.get("oidc_pkce_verifier").await.ok().flatten();
        let pkce_was_used: Option<bool> = session.get("oidc_pkce_used").await.ok().flatten();

        cleanup_oidc_session(&session).await;

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
        } else if pkce_was_used == Some(true) {
            return (
                StatusCode::BAD_REQUEST,
                Json(other_error(
                    "PKCE was enabled but verifier is missing from session (session may have expired)",
                )),
            )
                .into_response();
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

        let claims = match id_token.claims(&client.id_token_verifier(), &Nonce::new(stored_nonce)) {
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

        let user = match auth_session
            .backend
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

        if let Err(e) = auth_session.login(&user).await {
            tracing::error!("Failed to login user via OIDC: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(other_error("Failed to establish session")),
            )
                .into_response();
        }

        if let Err(e) = session.cycle_id().await {
            tracing::error!("Failed to cycle session ID after OIDC login: {:?}", e);
        }
        if let Some(frontend_url) = &oidc.frontend_base_url {
            Redirect::temporary(frontend_url).into_response()
        } else {
            Redirect::temporary("/").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
