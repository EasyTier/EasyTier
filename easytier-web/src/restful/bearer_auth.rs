use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Extension, FromRequestParts, Request};
use axum::http::{HeaderMap, StatusCode, header, request::Parts};
use axum::middleware::{self as axum_mw, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};

use crate::db::UserIdInDb;

use super::auth_state::{BearerTokenStore, ResolveTokenFailure};
use super::{other_error, users::User};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentUser {
    pub user_id: UserIdInDb,
    pub username: String,
    pub permissions: HashSet<String>,
}

impl CurrentUser {
    pub fn id(&self) -> UserIdInDb {
        self.user_id
    }

    async fn from_user(user: User, token_store: &BearerTokenStore) -> Result<Self, Response> {
        let permissions = token_store
            .backend()
            .get_group_permissions(&user)
            .await
            .map_err(|error| {
                tracing::warn!(
                    ?error,
                    user_id = user.id(),
                    "failed to load bearer user permissions"
                );
                unauthorized_response()
            })?
            .into_iter()
            .map(|permission| permission.name)
            .collect();

        Ok(Self {
            user_id: user.id(),
            username: user.db_user.username,
            permissions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAuthContext {
    pub current_user: CurrentUser,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerAuth {
    pub user: Option<CurrentUser>,
    pub token: String,
}

impl BearerAuth {
    pub fn current_user(&self) -> &CurrentUser {
        self.user
            .as_ref()
            .expect("BearerAuth is only constructed for authenticated requests")
    }

    pub fn user_id(&self) -> UserIdInDb {
        self.current_user().id()
    }
}

impl From<RequestAuthContext> for BearerAuth {
    fn from(value: RequestAuthContext) -> Self {
        Self {
            user: Some(value.current_user),
            token: value.token,
        }
    }
}

pub fn require_auth<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.route_layer(axum_mw::from_fn(bearer_auth_middleware))
}

pub async fn bearer_auth_middleware(
    Extension(token_store): Extension<Arc<BearerTokenStore>>,
    mut req: Request,
    next: Next,
) -> Response {
    let auth_context = match resolve_request_auth_context(req.headers(), token_store.as_ref()).await
    {
        Ok(auth_context) => auth_context,
        Err(response) => return response.into(),
    };

    req.extensions_mut()
        .insert(auth_context.current_user.clone());
    req.extensions_mut().insert(auth_context);
    next.run(req).await
}

#[async_trait]
impl<S> FromRequestParts<S> for BearerAuth
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Some(auth_context) = parts.extensions.get::<RequestAuthContext>().cloned() {
            return Ok(auth_context.into());
        }

        let Extension(token_store) =
            Extension::<Arc<BearerTokenStore>>::from_request_parts(parts, state)
                .await
                .map_err(|_| unauthorized_response())?;
        let auth_context = resolve_request_auth_context(&parts.headers, token_store.as_ref())
            .await
            .map_err(Response::from)?;
        parts.extensions.insert(auth_context.current_user.clone());
        parts.extensions.insert(auth_context.clone());
        Ok(auth_context.into())
    }
}

async fn resolve_request_auth_context(
    headers: &HeaderMap,
    token_store: &BearerTokenStore,
) -> Result<RequestAuthContext, AuthRejection> {
    let token = extract_bearer_token(headers)?;
    let token_context =
        token_store
            .resolve_token_detailed(&token)
            .map_err(|error| match error {
                ResolveTokenFailure::Missing
                | ResolveTokenFailure::Expired
                | ResolveTokenFailure::Revoked => AuthRejection::Unauthorized,
            })?;

    let user = token_store
        .backend()
        .find_user_by_id(token_context.user_id)
        .await
        .map_err(|error| {
            tracing::warn!(
                ?error,
                user_id = token_context.user_id,
                "failed to resolve bearer user"
            );
            AuthRejection::Unauthorized
        })?
        .ok_or_else(|| {
            token_store.remove(&token);
            AuthRejection::Unauthorized
        })?;

    let current_user = CurrentUser::from_user(user, token_store)
        .await
        .map_err(|_| AuthRejection::Unauthorized)?;
    Ok(RequestAuthContext {
        current_user,
        token,
    })
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, AuthRejection> {
    let raw_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthRejection::Unauthorized)?;

    let mut segments = raw_header.split_whitespace();
    let scheme = segments.next().ok_or(AuthRejection::Unauthorized)?;
    let token = segments.next().ok_or(AuthRejection::Unauthorized)?;

    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() || segments.next().is_some() {
        return Err(AuthRejection::Unauthorized);
    }

    Ok(token.to_string())
}

#[derive(Debug, Clone, Copy)]
enum AuthRejection {
    Unauthorized,
}

impl From<AuthRejection> for Response {
    fn from(_: AuthRejection) -> Self {
        unauthorized_response()
    }
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(other_error(
            "unauthorized: invalid or missing Authorization bearer token",
        )),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use serde_json::json;
    use tower::ServiceExt as _;

    use super::*;
    use crate::restful::users::Backend;
    use sea_orm::EntityTrait;

    async fn make_backend() -> Backend {
        Backend::new(crate::db::Db::memory_db().await)
    }

    async fn create_user(backend: &Backend, username: &str) -> UserIdInDb {
        backend
            .db()
            .create_user_and_join_users_group(
                username,
                password_auth::generate_hash("password-for-tests"),
            )
            .await
            .unwrap()
            .id
    }

    fn make_router(token_store: Arc<BearerTokenStore>) -> Router {
        require_auth(Router::new().route(
            "/protected",
            get(
                |auth: BearerAuth,
                 Extension(current_user): Extension<CurrentUser>,
                 Extension(context): Extension<RequestAuthContext>| async move {
                    Json(json!({
                        "auth_user_id": auth.user_id(),
                        "extension_user_id": current_user.user_id,
                        "context_user_id": context.current_user.user_id,
                        "token": context.token,
                    }))
                },
            ),
        ))
        .layer(Extension(token_store))
    }

    #[tokio::test]
    async fn token_auth_middleware_accepts_bearer() {
        let backend = make_backend().await;
        let user_id = create_user(&backend, "bearer-user").await;
        let token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let token = token_store.issue_token(user_id);
        let app = make_router(token_store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["auth_user_id"], user_id);
        assert_eq!(payload["extension_user_id"], user_id);
        assert_eq!(payload["context_user_id"], user_id);
        assert_eq!(payload["token"], token);
    }

    #[tokio::test]
    async fn token_auth_middleware_rejects_invalid_header() {
        let backend = make_backend().await;
        let user_id = create_user(&backend, "expired-user").await;
        let token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_millis(20),
            Duration::from_millis(10),
        ));
        let expired_token = token_store.issue_token(user_id);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let app = make_router(token_store);

        let requests = [
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, "Basic abc")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, "Bearer")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, "Bearer invalid token")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, "Bearer missing-token")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, format!("Bearer {expired_token}"))
                .body(Body::empty())
                .unwrap(),
        ];

        for request in requests {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn token_auth_middleware_rejects_deleted_user_and_removes_token() {
        let backend = make_backend().await;
        let user_id = create_user(&backend, "deleted-user").await;
        let token_store = Arc::new(BearerTokenStore::with_ttl_and_cleanup_interval(
            backend.clone(),
            Duration::from_secs(60),
            Duration::from_millis(10),
        ));
        let token = token_store.issue_token(user_id);
        crate::db::entity::users::Entity::delete_by_id(user_id)
            .exec(backend.db().orm_db())
            .await
            .unwrap();
        let app = make_router(token_store.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            token_store.resolve_token_detailed(&token),
            Err(ResolveTokenFailure::Missing)
        );
    }
}
