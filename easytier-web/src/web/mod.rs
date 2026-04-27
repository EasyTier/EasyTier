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
            serde_json::to_string(&ApiMetaResponse {
                api_host: api_host.to_string()
            })
            .unwrap(),
        ))
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
        router
    };

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
