use std::net::SocketAddr;

use axum::{routing::get, Router};
use easytier::common::scoped_task::ScopedTask;
use tokio::net::TcpListener;

pub struct RestfulServer {
    bind_addr: SocketAddr,

    serve_task: Option<ScopedTask<()>>,
}

impl RestfulServer {
    pub fn new(bind_addr: SocketAddr) -> Self {
        RestfulServer {
            bind_addr,
            serve_task: None,
        }
    }

    pub async fn start(&mut self) -> Result<(), anyhow::Error> {
        let listener = TcpListener::bind(self.bind_addr).await.unwrap();
        let app = Router::new().route("/", get(|| async { "Hello, World!" }));

        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        self.serve_task = Some(task.into());

        Ok(())
    }
}
