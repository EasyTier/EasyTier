pub mod session;
pub mod storage;

use std::sync::Arc;

use dashmap::DashMap;
use easytier::{
    common::scoped_task::ScopedTask, proto::web::HeartbeatRequest, tunnel::TunnelListener,
};
use session::Session;
use storage::{Storage, StorageToken};

use crate::db::Db;

#[derive(Debug)]
pub struct ClientManager {
    accept_task: Option<ScopedTask<()>>,
    clear_task: Option<ScopedTask<()>>,

    client_sessions: Arc<DashMap<url::Url, Arc<Session>>>,
    storage: Storage,
}

impl ClientManager {
    pub fn new(db: Db) -> Self {
        ClientManager {
            accept_task: None,
            clear_task: None,

            client_sessions: Arc::new(DashMap::new()),
            storage: Storage::new(db),
        }
    }

    pub async fn serve<L: TunnelListener + 'static>(
        &mut self,
        mut listener: L,
    ) -> Result<(), anyhow::Error> {
        listener.listen().await?;

        let sessions = self.client_sessions.clone();
        let storage = self.storage.weak_ref();
        let task = tokio::spawn(async move {
            while let Ok(tunnel) = listener.accept().await {
                let info = tunnel.info().unwrap();
                let client_url: url::Url = info.remote_addr.unwrap().into();
                println!("New session from {:?}", tunnel.info());
                let mut session = Session::new(storage.clone(), client_url.clone());
                session.serve(tunnel).await;
                sessions.insert(client_url, Arc::new(session));
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

    pub fn is_running(&self) -> bool {
        self.accept_task.is_some() && self.clear_task.is_some()
    }

    pub async fn list_sessions(&self) -> Vec<StorageToken> {
        let sessions = self
            .client_sessions
            .iter()
            .map(|item| item.value().clone())
            .collect::<Vec<_>>();

        let mut ret: Vec<StorageToken> = vec![];
        for s in sessions {
            if let Some(t) = s.get_token().await {
                ret.push(t);
            }
        }

        ret
    }

    pub fn get_session_by_machine_id(&self, machine_id: &uuid::Uuid) -> Option<Arc<Session>> {
        let c_url = self.storage.get_client_url_by_machine_id(machine_id)?;
        self.client_sessions
            .get(&c_url)
            .map(|item| item.value().clone())
    }

    pub async fn list_machine_by_token(&self, token: String) -> Vec<url::Url> {
        self.storage.list_token_clients(&token)
    }

    pub async fn get_heartbeat_requests(&self, client_url: &url::Url) -> Option<HeartbeatRequest> {
        let s = self.client_sessions.get(client_url)?.clone();
        s.data().read().await.req()
    }

    pub fn db(&self) -> &Db {
        self.storage.db()
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

    use crate::{client_manager::ClientManager, db::Db};

    #[tokio::test]
    async fn test_client() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:54333".parse().unwrap());
        let mut mgr = ClientManager::new(Db::memory_db().await);
        mgr.serve(Box::new(listener)).await.unwrap();

        let connector = UdpTunnelConnector::new("udp://127.0.0.1:54333".parse().unwrap());
        let _c = WebClient::new(connector, "test");

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
        println!("{:?}", mgr);
    }
}
