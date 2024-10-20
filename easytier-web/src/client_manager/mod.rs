pub mod session;

use std::{net::SocketAddr, sync::Arc};

use dashmap::DashMap;
use easytier::{common::scoped_task::ScopedTask, tunnel::TunnelListener};
use session::Session;

pub struct ClientManager {
    listener: Option<Box<dyn TunnelListener>>,

    accept_task: Option<ScopedTask<()>>,
    clear_task: Option<ScopedTask<()>>,

    client_sessions: Arc<DashMap<url::Url, Session>>,
}

impl ClientManager {
    pub fn new(listener: Box<dyn TunnelListener>) -> Self {
        ClientManager {
            listener: Some(listener),

            accept_task: None,
            clear_task: None,

            client_sessions: Arc::new(DashMap::new()),
        }
    }

    pub async fn serve(&mut self) -> Result<(), anyhow::Error> {
        let mut listener = self.listener.take().unwrap();
        listener.listen().await?;

        let sessions = self.client_sessions.clone();
        let task = tokio::spawn(async move {
            while let Ok(tunnel) = listener.accept().await {
                let info = tunnel.info().unwrap();
                println!("New session from {:?}", tunnel.info());
                let session = Session::new(tunnel);
                sessions.insert(info.remote_addr.unwrap().into(), session);
            }
        });

        self.accept_task = Some(ScopedTask::from(task));

        let sessions = self.client_sessions.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                sessions.retain(|_, session| session.is_running());
            }
        });
        self.clear_task = Some(ScopedTask::from(task));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use easytier::{
        tunnel::{
            common::tests::wait_for_condition,
            udp::{UdpTunnelConnector, UdpTunnelListener},
        },
        web_client::WebClient,
    };

    use crate::client_manager::ClientManager;

    #[tokio::test]
    async fn test_client() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:54333".parse().unwrap());
        let mut mgr = ClientManager::new(Box::new(listener));
        mgr.serve().await.unwrap();

        let connector = UdpTunnelConnector::new("udp://127.0.0.1:54333".parse().unwrap());
        let _c = WebClient::new(connector);

        wait_for_condition(
            || async { mgr.client_sessions.len() == 1 },
            Duration::from_secs(6),
        )
        .await;

        let mut a = mgr
            .client_sessions
            .iter()
            .next()
            .unwrap()
            .data()
            .read()
            .await
            .heartbeat_waiter();
        let req = a.recv().await.unwrap();
        println!("{:?}", req);
    }
}
