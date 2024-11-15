use std::sync::{Arc, Weak};

use dashmap::{DashMap, DashSet};

use crate::db::Db;

// use this to maintain Storage
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageToken {
    pub token: String,
    pub client_url: url::Url,
    pub machine_id: uuid::Uuid,
}

#[derive(Debug)]
pub struct StorageInner {
    // some map for indexing
    pub token_clients_map: DashMap<String, DashSet<url::Url>>,
    pub machine_client_url_map: DashMap<uuid::Uuid, DashSet<url::Url>>,
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

    pub fn add_client(&self, stoken: StorageToken) {
        let inner = self
            .0
            .token_clients_map
            .entry(stoken.token)
            .or_insert_with(DashSet::new);
        inner.insert(stoken.client_url.clone());

        self.0
            .machine_client_url_map
            .entry(stoken.machine_id)
            .or_insert_with(DashSet::new)
            .insert(stoken.client_url.clone());
    }

    pub fn remove_client(&self, stoken: &StorageToken) {
        self.0.token_clients_map.remove_if(&stoken.token, |_, set| {
            set.remove(&stoken.client_url);
            set.is_empty()
        });

        self.0
            .machine_client_url_map
            .remove_if(&stoken.machine_id, |_, set| {
                set.remove(&stoken.client_url);
                set.is_empty()
            });
    }

    pub fn weak_ref(&self) -> WeakRefStorage {
        Arc::downgrade(&self.0)
    }

    pub fn get_client_url_by_machine_id(&self, machine_id: &uuid::Uuid) -> Option<url::Url> {
        self.0
            .machine_client_url_map
            .get(&machine_id)
            .map(|url| url.iter().next().map(|url| url.clone()))
            .flatten()
    }

    pub fn list_token_clients(&self, token: &str) -> Vec<url::Url> {
        self.0
            .token_clients_map
            .get(token)
            .map(|set| set.iter().map(|url| url.clone()).collect())
            .unwrap_or_default()
    }

    pub fn db(&self) -> &Db {
        &self.0.db
    }
}
