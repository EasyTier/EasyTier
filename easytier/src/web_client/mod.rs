use std::sync::Arc;

use crate::{common::scoped_task::ScopedTask, tunnel::TunnelConnector};

pub mod controller;
pub mod session;

pub struct WebClient {
    controller: Arc<controller::Controller>,
    tasks: ScopedTask<()>,
}

impl WebClient {
    pub fn new<T: TunnelConnector + 'static>(connector: T) -> Self {
        let controller = Arc::new(controller::Controller::new());

        let controller_clone = controller.clone();
        let tasks = ScopedTask::from(tokio::spawn(async move {
            Self::routine(controller_clone, Box::new(connector)).await;
        }));

        WebClient { controller, tasks }
    }

    async fn routine(
        controller: Arc<controller::Controller>,
        mut connector: Box<dyn TunnelConnector>,
    ) {
        loop {
            let Ok(conn) = connector.connect().await else {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            };

            let mut session = session::Session::new(conn, controller.clone());
            session.wait().await;
        }
    }
}
