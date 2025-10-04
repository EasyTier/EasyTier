pub mod session;
pub mod storage;

use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};

use dashmap::DashMap;
use easytier::{proto::web::HeartbeatRequest, tunnel::TunnelListener};
use maxminddb::geoip2;
use session::{Location, Session};
use storage::{Storage, StorageToken};
use tokio::task::JoinSet;

use crate::db::{Db, UserIdInDb};

#[derive(rust_embed::Embed)]
#[folder = "resources/"]
#[include = "geoip2-cn.mmdb"]
struct GeoipDb;

fn load_geoip_db(geoip_db: Option<String>) -> Option<maxminddb::Reader<Vec<u8>>> {
    if let Some(path) = geoip_db {
        match maxminddb::Reader::open_readfile(&path) {
            Ok(reader) => {
                tracing::info!("Successfully loaded GeoIP2 database from {}", path);
                Some(reader)
            }
            Err(err) => {
                tracing::debug!("Failed to load GeoIP2 database from {}: {}", path, err);
                None
            }
        }
    } else {
        let db = GeoipDb::get("geoip2-cn.mmdb").unwrap();
        let reader = maxminddb::Reader::from_source(db.data.to_vec()).ok()?;
        tracing::info!("Successfully loaded GeoIP2 database from embedded file");
        Some(reader)
    }
}

#[derive(Debug)]
pub struct ClientManager {
    tasks: JoinSet<()>,

    listeners_cnt: Arc<AtomicU32>,

    client_sessions: Arc<DashMap<url::Url, Arc<Session>>>,
    storage: Storage,

    geoip_db: Arc<Option<maxminddb::Reader<Vec<u8>>>>,
}

impl ClientManager {
    pub fn new(db: Db, geoip_db: Option<String>) -> Self {
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
            geoip_db: Arc::new(load_geoip_db(geoip_db)),
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
        let geoip_db = self.geoip_db.clone();
        self.tasks.spawn(async move {
            while let Ok(tunnel) = listener.accept().await {
                let info = tunnel.info().unwrap();
                let client_url: url::Url = info.remote_addr.unwrap().into();
                let location = Self::lookup_location(&client_url, geoip_db.clone());
                tracing::info!(
                    "New session from {:?}, location: {:?}",
                    client_url,
                    location
                );
                let mut session = Session::new(storage.clone(), client_url.clone(), location);
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

    pub async fn get_machine_location(&self, client_url: &url::Url) -> Option<Location> {
        let s = self.client_sessions.get(client_url)?.clone();
        s.data().read().await.location().cloned()
    }

    pub fn db(&self) -> &Db {
        self.storage.db()
    }

    fn lookup_location(
        client_url: &url::Url,
        geoip_db: Arc<Option<maxminddb::Reader<Vec<u8>>>>,
    ) -> Option<Location> {
        let host = client_url.host_str()?;
        let ip: std::net::IpAddr = if let Ok(ip) = host.parse() {
            ip
        } else {
            tracing::debug!("Failed to parse host as IP address: {}", host);
            return None;
        };

        // Skip lookup for private/special IPs
        let is_private = match ip {
            std::net::IpAddr::V4(ipv4) => {
                ipv4.is_private() || ipv4.is_loopback() || ipv4.is_unspecified()
            }
            std::net::IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
        };

        if is_private {
            tracing::debug!("Skipping GeoIP lookup for special IP: {}", ip);
            let location = Location {
                country: "本地网络".to_string(),
                city: None,
                region: None,
            };
            return Some(location);
        }

        let location = if let Some(db) = &*geoip_db {
            match db.lookup::<geoip2::City>(ip) {
                Ok(city) => {
                    let country = city
                        .country
                        .and_then(|c| c.names)
                        .and_then(|n| {
                            n.get("zh-CN")
                                .or_else(|| n.get("en"))
                                .map(|s| s.to_string())
                        })
                        .unwrap_or_else(|| "海外".to_string());

                    let city_name = city.city.and_then(|c| c.names).and_then(|n| {
                        n.get("zh-CN")
                            .or_else(|| n.get("en"))
                            .map(|s| s.to_string())
                    });

                    let region = city.subdivisions.map(|r| {
                        r.iter()
                            .filter_map(|x| x.names.as_ref())
                            .filter_map(|x| x.get("zh-CN").or_else(|| x.get("en")))
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    });

                    Location {
                        country,
                        city: city_name,
                        region,
                    }
                }
                Err(err) => {
                    tracing::debug!("GeoIP lookup failed for {}: {}", ip, err);
                    Location {
                        country: "海外".to_string(),
                        city: None,
                        region: None,
                    }
                }
            }
        } else {
            tracing::debug!(
                "GeoIP database not available, using default location for {}",
                ip
            );
            Location {
                country: "海外".to_string(),
                city: None,
                region: None,
            }
        };

        Some(location)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use easytier::{
        instance_manager::NetworkInstanceManager,
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
        let mut mgr = ClientManager::new(Db::memory_db().await, None);
        mgr.add_listener(Box::new(listener)).await.unwrap();

        mgr.db()
            .inner()
            .execute("INSERT INTO users (username, password) VALUES ('test', 'test')")
            .await
            .unwrap();

        let connector = UdpTunnelConnector::new("udp://127.0.0.1:54333".parse().unwrap());
        let _c = WebClient::new(
            connector,
            "test",
            "test",
            Arc::new(NetworkInstanceManager::new()),
        );

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
