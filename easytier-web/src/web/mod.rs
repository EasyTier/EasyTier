use axum::Router;
use easytier::common::scoped_task::ScopedTask;
use rust_embed::RustEmbed;
use std::net::SocketAddr;
use axum_embed::ServeEmbed;
use tokio::net::TcpListener;

/// Embed assets for web dashboard, build frontend first
#[derive(RustEmbed, Clone)]
#[folder = "frontend/dist/"]
struct Assets;

pub struct WebServer {
    bind_addr: SocketAddr,
    serve_task: Option<ScopedTask<()>>,
}

impl WebServer {
    pub async fn new(bind_addr: SocketAddr) -> anyhow::Result<Self> {
        Ok(WebServer {
            bind_addr,
            serve_task: None,
        })
    }

    pub async fn start(&mut self) -> Result<(), anyhow::Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        let service = ServeEmbed::<Assets>::new();
        let app = Router::new().fallback_service(service);

        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        self.serve_task = Some(task.into());

        Ok(())
    }
}
