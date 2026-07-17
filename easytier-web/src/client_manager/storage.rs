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
    authorized: bool,
}

#[derive(Debug)]
pub struct StorageInner {
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

    fn remove_client_info_map(map: &DashMap<uuid::Uuid, ClientInfo>, stoken: &StorageToken) {
        map.remove_if(&stoken.machine_id, |_, v| {
            v.storage_token.client_url == stoken.client_url
                && v.storage_token.user_id == stoken.user_id
        });
    }

    fn update_client_info_map(map: &DashMap<uuid::Uuid, ClientInfo>, client_info: &ClientInfo) {
        map.entry(client_info.storage_token.machine_id)
            .and_modify(|e| {
                let same_client = e.storage_token.client_url
                    == client_info.storage_token.client_url
                    && e.storage_token.user_id == client_info.storage_token.user_id;
                let should_replace = if (same_client && e.authorized != client_info.authorized)
                    || (!e.authorized && client_info.authorized)
                {
                    true
                } else if e.authorized && !client_info.authorized && !same_client {
                    false
                } else {
                    e.report_time < client_info.report_time
                };
                if should_replace {
                    assert_eq!(
                        e.storage_token.machine_id,
                        client_info.storage_token.machine_id
                    );
                    *e = client_info.clone();
                }
            })
            .or_insert(client_info.clone());
    }

    pub fn update_client(&self, stoken: StorageToken, report_time: i64, authorized: bool) {
        let inner = self.0.user_clients_map.entry(stoken.user_id).or_default();

        let client_info = ClientInfo {
            storage_token: stoken.clone(),
            report_time,
            authorized,
        };
        Self::update_client_info_map(&inner, &client_info);
    }

    pub fn remove_client(&self, stoken: &StorageToken) {
        self.0
            .user_clients_map
            .remove_if(&stoken.user_id, |_, set| {
                Self::remove_client_info_map(set, stoken);
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
        self.get_client_url_by_machine_id_with_auth(user_id, machine_id, true)
    }

    pub fn get_client_url_by_machine_id_with_auth(
        &self,
        user_id: UserIdInDb,
        machine_id: &uuid::Uuid,
        require_authorized: bool,
    ) -> Option<url::Url> {
        self.0.user_clients_map.get(&user_id).and_then(|info_map| {
            info_map.get(machine_id).and_then(|info| {
                (!require_authorized || info.authorized)
                    .then(|| info.storage_token.client_url.clone())
            })
        })
    }

    pub fn list_user_clients(&self, user_id: UserIdInDb) -> Vec<url::Url> {
        self.0
            .user_clients_map
            .get(&user_id)
            .map(|info_map| {
                info_map
                    .iter()
                    .filter(|info| info.value().authorized)
                    .map(|info| info.value().storage_token.client_url.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn list_clients(&self) -> Vec<StorageToken> {
        self.list_clients_with_auth(true)
    }

    pub fn list_all_clients(&self) -> Vec<StorageToken> {
        self.list_clients_with_auth(false)
    }

    fn list_clients_with_auth(&self, require_authorized: bool) -> Vec<StorageToken> {
        self.0
            .user_clients_map
            .iter()
            .flat_map(|user_clients| {
                user_clients
                    .value()
                    .iter()
                    .filter(|info| !require_authorized || info.value().authorized)
                    .map(|info| info.value().storage_token.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub fn db(&self) -> &Db {
        &self.0.db
    }

    pub async fn auto_create_user(&self, username: &str) -> anyhow::Result<UserIdInDb> {
        let new_user = self.db().auto_create_user(username).await?;
        tracing::info!("Auto-created user '{}' with id {}", username, new_user.id);
        Ok(new_user.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_storage_token(
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
        client_url: &str,
    ) -> StorageToken {
        StorageToken {
            token: format!("token-{machine_id}"),
            client_url: client_url.parse().unwrap(),
            machine_id,
            user_id,
        }
    }

    #[tokio::test]
    async fn machine_id_is_scoped_within_each_user() {
        let storage = Storage::new(Db::memory_db().await);
        let machine_id = uuid::Uuid::new_v4();

        let user1_token = make_storage_token(1, machine_id, "tcp://127.0.0.1:1001");
        let user2_token = make_storage_token(2, machine_id, "tcp://127.0.0.1:1002");

        storage.update_client(user1_token.clone(), 10, true);
        storage.update_client(user2_token.clone(), 20, true);

        assert_eq!(
            storage.get_client_url_by_machine_id(1, &machine_id),
            Some(user1_token.client_url.clone())
        );
        assert_eq!(
            storage.get_client_url_by_machine_id(2, &machine_id),
            Some(user2_token.client_url.clone())
        );

        storage.remove_client(&user1_token);

        assert_eq!(storage.get_client_url_by_machine_id(1, &machine_id), None);
        assert_eq!(
            storage.get_client_url_by_machine_id(2, &machine_id),
            Some(user2_token.client_url.clone())
        );

        storage.remove_client(&user2_token);

        assert_eq!(storage.get_client_url_by_machine_id(2, &machine_id), None);
    }

    #[tokio::test]
    async fn list_clients_returns_current_storage_tokens() {
        let storage = Storage::new(Db::memory_db().await);
        let user1_token = make_storage_token(1, uuid::Uuid::new_v4(), "tcp://127.0.0.1:1001");
        let user2_token = make_storage_token(2, uuid::Uuid::new_v4(), "tcp://127.0.0.1:1002");

        storage.update_client(user1_token.clone(), 10, true);
        storage.update_client(user2_token.clone(), 20, true);

        let tokens = storage.list_clients();
        assert_eq!(tokens.len(), 2);
        assert!(tokens.iter().any(|token| token.token == user1_token.token));
        assert!(tokens.iter().any(|token| token.token == user2_token.token));

        storage.remove_client(&user1_token);

        let tokens = storage.list_clients();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, user2_token.token);
    }

    #[tokio::test]
    async fn pending_client_is_listed_but_not_authorized_for_machine_lookup() {
        let storage = Storage::new(Db::memory_db().await);
        let machine_id = uuid::Uuid::new_v4();
        let token = make_storage_token(1, machine_id, "tcp://127.0.0.1:1001");

        storage.update_client(token.clone(), 10, false);

        assert_eq!(storage.list_clients().len(), 0);
        assert_eq!(storage.list_all_clients().len(), 1);
        assert_eq!(storage.list_user_clients(1), Vec::<url::Url>::new());
        assert_eq!(storage.get_client_url_by_machine_id(1, &machine_id), None);
        assert_eq!(
            storage.get_client_url_by_machine_id_with_auth(1, &machine_id, false),
            Some(token.client_url.clone())
        );

        storage.update_client(token.clone(), 11, true);

        assert_eq!(
            storage.get_client_url_by_machine_id(1, &machine_id),
            Some(token.client_url.clone())
        );

        storage.update_client(token.clone(), 11, false);

        assert_eq!(storage.get_client_url_by_machine_id(1, &machine_id), None);
        assert_eq!(storage.list_clients().len(), 0);
        assert_eq!(storage.list_all_clients().len(), 1);
    }

    #[tokio::test]
    async fn stale_client_authorization_update_does_not_replace_newer_client() {
        let storage = Storage::new(Db::memory_db().await);
        let machine_id = uuid::Uuid::new_v4();
        let old_token = make_storage_token(1, machine_id, "tcp://127.0.0.1:1001");
        let new_token = make_storage_token(1, machine_id, "tcp://127.0.0.1:1002");

        storage.update_client(old_token.clone(), 10, true);
        storage.update_client(new_token.clone(), 20, true);
        storage.update_client(old_token, 10, false);

        assert_eq!(
            storage.get_client_url_by_machine_id(1, &machine_id),
            Some(new_token.client_url)
        );
    }

    #[tokio::test]
    async fn pending_client_does_not_replace_authorized_route() {
        let storage = Storage::new(Db::memory_db().await);
        let machine_id = uuid::Uuid::new_v4();
        let authorized_token = make_storage_token(1, machine_id, "tcp://127.0.0.1:1001");
        let pending_token = make_storage_token(1, machine_id, "tcp://127.0.0.1:1002");

        storage.update_client(authorized_token.clone(), 10, true);
        storage.update_client(pending_token, i64::MAX, false);

        assert_eq!(
            storage.get_client_url_by_machine_id(1, &machine_id),
            Some(authorized_token.client_url)
        );
    }

    #[tokio::test]
    async fn authorized_client_replaces_pending_route_regardless_of_report_time() {
        let storage = Storage::new(Db::memory_db().await);
        let machine_id = uuid::Uuid::new_v4();
        let pending_token = make_storage_token(1, machine_id, "tcp://127.0.0.1:1001");
        let authorized_token = make_storage_token(1, machine_id, "tcp://127.0.0.1:1002");

        storage.update_client(pending_token, i64::MAX, false);
        storage.update_client(authorized_token.clone(), 10, true);

        assert_eq!(
            storage.get_client_url_by_machine_id(1, &machine_id),
            Some(authorized_token.client_url)
        );
    }
}
