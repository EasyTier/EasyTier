use std::sync::{Arc, Weak};

use dashmap::DashMap;

use crate::db::Db;

// use this to maintain Storage
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageToken {
    pub token: String,
    pub client_url: url::Url,
    pub machine_id: uuid::Uuid,
}

#[derive(Debug, Clone)]
struct ClientInfo {
    client_url: url::Url,
    machine_id: uuid::Uuid,
    token: String,
    report_time: i64,
}

#[derive(Debug)]
pub struct StorageInner {
    // some map for indexing
    token_clients_map: DashMap<String, DashMap<uuid::Uuid, ClientInfo>>,
    machine_client_url_map: DashMap<uuid::Uuid, ClientInfo>,
    pub db: Db,
}

#[derive(Debug, Clone)]
pub struct Storage(Arc<StorageInner>);
pub type WeakRefStorage = Weak<StorageInner>;

impl TryFrom<WeakRefStorage> for Storage {
    type Error = ();

    fn try_from(weak: Weak<StorageInner>) -> Result<Self, Self::Error> {
        weak.upgrade().map(|inner| Storage(inner)).ok_or(())
    }
}

impl Storage {
    pub fn new(db: Db) -> Self {
        Storage(Arc::new(StorageInner {
            token_clients_map: DashMap::new(),
            machine_client_url_map: DashMap::new(),
            db,
        }))
    }

    fn remove_mid_to_client_info_map(
        map: &DashMap<uuid::Uuid, ClientInfo>,
        machine_id: &uuid::Uuid,
        client_url: &url::Url,
    ) {
        map.remove_if(&machine_id, |_, v| v.client_url == *client_url);
    }

    fn update_mid_to_client_info_map(
        map: &DashMap<uuid::Uuid, ClientInfo>,
        client_info: &ClientInfo,
    ) {
        map.entry(client_info.machine_id)
            .and_modify(|e| {
                if e.report_time < client_info.report_time {
                    assert_eq!(e.machine_id, client_info.machine_id);
                    *e = client_info.clone();
                }
            })
            .or_insert(client_info.clone());
    }

    pub fn update_client(&self, stoken: StorageToken, report_time: i64) {
        let inner = self
            .0
            .token_clients_map
            .entry(stoken.token.clone())
            .or_insert_with(DashMap::new);

        let client_info = ClientInfo {
            client_url: stoken.client_url.clone(),
            machine_id: stoken.machine_id,
            token: stoken.token.clone(),
            report_time,
        };

        Self::update_mid_to_client_info_map(&inner, &client_info);
        Self::update_mid_to_client_info_map(&self.0.machine_client_url_map, &client_info);
    }

    pub fn remove_client(&self, stoken: &StorageToken) {
        self.0.token_clients_map.remove_if(&stoken.token, |_, set| {
            Self::remove_mid_to_client_info_map(set, &stoken.machine_id, &stoken.client_url);
            set.is_empty()
        });

        Self::remove_mid_to_client_info_map(
            &self.0.machine_client_url_map,
            &stoken.machine_id,
            &stoken.client_url,
        );
    }

    pub fn weak_ref(&self) -> WeakRefStorage {
        Arc::downgrade(&self.0)
    }

    pub fn get_client_url_by_machine_id(&self, machine_id: &uuid::Uuid) -> Option<url::Url> {
        self.0
            .machine_client_url_map
            .get(&machine_id)
            .map(|info| info.client_url.clone())
    }

    pub fn list_token_clients(&self, token: &str) -> Vec<url::Url> {
        self.0
            .token_clients_map
            .get(token)
            .map(|info_map| {
                info_map
                    .iter()
                    .map(|info| info.value().client_url.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn db(&self) -> &Db {
        &self.0.db
    }
}
