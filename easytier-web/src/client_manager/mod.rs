pub mod session;
pub mod storage;

use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};

use dashmap::DashMap;
use easytier::{proto::web::HeartbeatRequest, tunnel::TunnelListener};
use session::Session;
use storage::{Storage, StorageToken};
use tokio::task::JoinSet;

use crate::db::{Db, UserIdInDb};

#[derive(Debug)]
pub struct ClientManager {
    tasks: JoinSet<()>,

    listeners_cnt: Arc<AtomicU32>,

    client_sessions: Arc<DashMap<url::Url, Arc<Session>>>,
    storage: Storage,
}

impl ClientManager {
    pub fn new(db: Db) -> Self {
        let client_sessions = Arc::new(DashMap::new());
        let sessions: Arc<DashMap<url::Url, Arc<Session>>> = client_sessions.clone();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                sessions.retain(|_, session| session.is_running());
            }
        });
        ClientManager {
            tasks,

            listeners_cnt: Arc::new(AtomicU32::new(0)),

            client_sessions,
            storage: Storage::new(db),
        }
    }

    pub async fn add_listener<L: TunnelListener + 'static>(
        &mut self,
        mut listener: L,
    ) -> Result<(), anyhow::Error> {
        listener.listen().await?;
        self.listeners_cnt.fetch_add(1, Ordering::Relaxed);
        let sessions = self.client_sessions.clone();
        let storage = self.storage.weak_ref();
        let listeners_cnt = self.listeners_cnt.clone();
        self.tasks.spawn(async move {
            while let Ok(tunnel) = listener.accept().await {
                let info = tunnel.info().unwrap();
                let client_url: url::Url = info.remote_addr.unwrap().into();
                println!("New session from {:?}", tunnel.info());
                let mut session = Session::new(storage.clone(), client_url.clone());
                session.serve(tunnel).await;
                sessions.insert(client_url, Arc::new(session));
            }
            listeners_cnt.fetch_sub(1, Ordering::Relaxed);
        });

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.listeners_cnt.load(Ordering::Relaxed) > 0
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

    pub fn get_session_by_machine_id(
        &self,
        user_id: UserIdInDb,
        machine_id: &uuid::Uuid,
    ) -> Option<Arc<Session>> {
        let c_url = self
            .storage
            .get_client_url_by_machine_id(user_id, machine_id)?;
        self.client_sessions
            .get(&c_url)
            .map(|item| item.value().clone())
    }

    pub async fn list_machine_by_user_id(&self, user_id: UserIdInDb) -> Vec<url::Url> {
        self.storage.list_user_clients(user_id)
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
    use sqlx::Executor;

    use crate::{client_manager::ClientManager, db::Db};

    #[tokio::test]
    async fn test_client() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:54333".parse().unwrap());
        let mut mgr = ClientManager::new(Db::memory_db().await);
        mgr.add_listener(Box::new(listener)).await.unwrap();

        mgr.db()
            .inner()
            .execute("INSERT INTO users (username, password) VALUES ('test', 'test')")
            .await
            .unwrap();

        let connector = UdpTunnelConnector::new("udp://127.0.0.1:54333".parse().unwrap());
        let _c = WebClient::new(connector, "test", "test");

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
