use axum::{
    Router,
    extract::State,
    http::header,
    response::{IntoResponse, Response},
    routing,
};
use axum_embed::ServeEmbed;
use rust_embed::RustEmbed;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_util::task::AbortOnDropHandle;

/// Embed assets for web dashboard, build frontend first
#[derive(RustEmbed, Clone)]
#[folder = "frontend/dist/"]
struct Assets;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ApiMetaResponse {
    api_host: String,
}

async fn handle_api_meta(State(api_host): State<url::Url>) -> impl IntoResponse {
    api_meta_response(api_host.to_string())
}

// The frontend dist may bundle a static api_meta.js pointing at the official
// hosted console. Without --api-host this server is the API origin, so the
// bundled file must be overridden to keep the frontend on relative requests
// instead of sending credentials to a third-party domain.
async fn handle_same_origin_api_meta() -> impl IntoResponse {
    api_meta_response(String::new())
}

fn api_meta_response(api_host: String) -> Response<String> {
    Response::builder()
        .header(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .header(header::PRAGMA, "no-cache")
        .header(header::EXPIRES, "0")
        .body(format!(
            "window.apiMeta = {}",
            serde_json::to_string(&ApiMetaResponse { api_host }).unwrap(),
        ))
        .unwrap()
}

// The hashed asset filenames change on every build, but browsers happily
// serve index.html from their heuristic cache and keep loading the old
// bundle. Serve the entry document explicitly with no-cache so upgrades are
// picked up on the next reload.
async fn handle_index() -> impl IntoResponse {
    let asset = Assets::get("index.html").expect("frontend dist must contain index.html");
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .header(header::PRAGMA, "no-cache")
        .header(header::EXPIRES, "0")
        .body(String::from_utf8_lossy(&asset.data).to_string())
        .unwrap()
}

pub fn build_router(api_host: Option<url::Url>) -> Router {
    let service = ServeEmbed::<Assets>::new();
    let router = Router::new();

    let router = if let Some(api_host) = api_host {
        let sub_router = Router::new()
            .route("/api_meta.js", routing::get(handle_api_meta))
            .with_state(api_host);
        router.merge(sub_router)
    } else {
        router.route("/api_meta.js", routing::get(handle_same_origin_api_meta))
    };

    let router = router
        .route("/", routing::get(handle_index))
        .route("/index.html", routing::get(handle_index));

    router.fallback_service(service)
}

pub struct WebServer {
    bind_addr: SocketAddr,
    router: Router,
    serve_task: Option<AbortOnDropHandle<()>>,
}

impl WebServer {
    pub async fn new(bind_addr: SocketAddr, router: Router) -> anyhow::Result<Self> {
        Ok(WebServer {
            bind_addr,
            router,
            serve_task: None,
        })
    }

    pub async fn start(self) -> Result<AbortOnDropHandle<()>, anyhow::Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        let app = self.router;

        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));

        Ok(task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn get_api_meta(router: Router) -> String {
        let response = router
            .oneshot(
                Request::get("/api_meta.js")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn same_origin_mode_overrides_bundled_api_meta() {
        // Without --api-host the server itself is the API origin and must
        // neutralize the api_meta.js bundled with the frontend dist, which
        // points at the official hosted console.
        let body = get_api_meta(build_router(None)).await;
        assert_eq!(body, "window.apiMeta = {\"api_host\":\"\"}");
    }

    #[tokio::test]
    async fn index_html_is_served_with_no_cache() {
        for path in ["/", "/index.html"] {
            let response = build_router(None)
                .oneshot(Request::get(path).body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "no-cache, no-store, must-revalidate"
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(body.contains("<div id=\"app\">"), "path: {path}");
        }
    }

    #[tokio::test]
    async fn explicit_api_host_is_injected() {
        let body = get_api_meta(build_router(Some(
            "https://api.example.com".parse().unwrap(),
        )))
        .await;
        assert_eq!(
            body,
            "window.apiMeta = {\"api_host\":\"https://api.example.com/\"}"
        );
    }
}
