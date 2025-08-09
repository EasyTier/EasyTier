use std::sync::{Arc, Weak};

use dashmap::DashMap;

use crate::db::{Db, UserIdInDb};

// use this to maintain Storage
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageToken {
    pub token: String,
    pub client_url: url::Url,
    pub machine_id: uuid::Uuid,
    pub user_id: UserIdInDb,
}

#[derive(Debug, Clone)]
struct ClientInfo {
    storage_token: StorageToken,
    report_time: i64,
}

#[derive(Debug)]
pub struct StorageInner {
    // some map for indexing
    user_clients_map: DashMap<UserIdInDb, DashMap<uuid::Uuid, ClientInfo>>,
    pub db: Db,
}

#[derive(Debug, Clone)]
pub struct Storage(Arc<StorageInner>);
pub type WeakRefStorage = Weak<StorageInner>;

impl TryFrom<WeakRefStorage> for Storage {
    type Error = ();

    fn try_from(weak: Weak<StorageInner>) -> Result<Self, Self::Error> {
        weak.upgrade().map(Storage).ok_or(())
    }
}

impl Storage {
    pub fn new(db: Db) -> Self {
        Storage(Arc::new(StorageInner {
            user_clients_map: DashMap::new(),
            db,
        }))
    }

    fn remove_mid_to_client_info_map(
        map: &DashMap<uuid::Uuid, ClientInfo>,
        machine_id: &uuid::Uuid,
        client_url: &url::Url,
    ) {
        map.remove_if(machine_id, |_, v| v.storage_token.client_url == *client_url);
    }

    fn update_mid_to_client_info_map(
        map: &DashMap<uuid::Uuid, ClientInfo>,
        client_info: &ClientInfo,
    ) {
        map.entry(client_info.storage_token.machine_id)
            .and_modify(|e| {
                if e.report_time < client_info.report_time {
                    assert_eq!(
                        e.storage_token.machine_id,
                        client_info.storage_token.machine_id
                    );
                    *e = client_info.clone();
                }
            })
            .or_insert(client_info.clone());
    }

    pub fn update_client(&self, stoken: StorageToken, report_time: i64) {
        let inner = self.0.user_clients_map.entry(stoken.user_id).or_default();

        let client_info = ClientInfo {
            storage_token: stoken.clone(),
            report_time,
        };

        Self::update_mid_to_client_info_map(&inner, &client_info);
    }

    pub fn remove_client(&self, stoken: &StorageToken) {
        self.0
            .user_clients_map
            .remove_if(&stoken.user_id, |_, set| {
                Self::remove_mid_to_client_info_map(set, &stoken.machine_id, &stoken.client_url);
                set.is_empty()
            });
    }

    pub fn weak_ref(&self) -> WeakRefStorage {
        Arc::downgrade(&self.0)
    }

    pub fn get_client_url_by_machine_id(
        &self,
        user_id: UserIdInDb,
        machine_id: &uuid::Uuid,
    ) -> Option<url::Url> {
        self.0.user_clients_map.get(&user_id).and_then(|info_map| {
            info_map
                .get(machine_id)
                .map(|info| info.storage_token.client_url.clone())
        })
    }

    pub fn list_user_clients(&self, user_id: UserIdInDb) -> Vec<url::Url> {
        self.0
            .user_clients_map
            .get(&user_id)
            .map(|info_map| {
                info_map
                    .iter()
                    .map(|info| info.value().storage_token.client_url.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn db(&self) -> &Db {
        &self.0.db
    }
}
