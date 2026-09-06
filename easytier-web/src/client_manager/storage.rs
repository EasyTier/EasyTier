use std::sync::{Arc, Weak};

use dashmap::{DashMap, mapref::entry::Entry};

use crate::db::{Db, UserIdInDb};

use super::session::{
    ManagedConfigPersistedChange, ManagedConfigReconcileHint, ManagedRuntimeState,
    SharedManagedRuntimeState, record_managed_config_reconcile_hint,
};

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
    session_epoch: u64,
}

#[derive(Debug, Clone)]
struct ManagedRuntimeContinuity {
    // Accepted trade-off: continuity assumes managed configuration is only
    // mutated through easytier-web. A local management RPC can make Core
    // drift without invalidating this state; detecting that would require a
    // Core-wide mutation generation outside this compatibility path.
    runtime_id: Option<uuid::Uuid>,
    session_epoch: u64,
    state: SharedManagedRuntimeState,
}

#[derive(Debug)]
pub struct StorageInner {
    user_clients_map: DashMap<UserIdInDb, DashMap<uuid::Uuid, ClientInfo>>,
    managed_runtime_states: DashMap<(UserIdInDb, uuid::Uuid), ManagedRuntimeContinuity>,
    pub db: Db,
}

impl StorageInner {
    pub(super) fn owns_authorized_session(
        &self,
        stoken: &StorageToken,
        session_epoch: u64,
    ) -> bool {
        self.user_clients_map
            .get(&stoken.user_id)
            .and_then(|clients| {
                clients.get(&stoken.machine_id).map(|client| {
                    client.authorized
                        && client.session_epoch == session_epoch
                        && client.storage_token.token == stoken.token
                        && client.storage_token.client_url == stoken.client_url
                        && client.storage_token.user_id == stoken.user_id
                        && client.storage_token.machine_id == stoken.machine_id
                })
            })
            .unwrap_or(false)
    }
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
            managed_runtime_states: DashMap::new(),
            db,
        }))
    }

    pub(super) fn bind_managed_runtime_state(
        &self,
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
        runtime_id: Option<uuid::Uuid>,
        session_epoch: u64,
    ) -> SharedManagedRuntimeState {
        let new_state = || Arc::new(std::sync::Mutex::new(ManagedRuntimeState::default()));
        match self.0.managed_runtime_states.entry((user_id, machine_id)) {
            Entry::Occupied(mut entry) => {
                let current = entry.get();
                if runtime_id.is_some() && current.runtime_id == runtime_id {
                    let state = current.state.clone();
                    if session_epoch > current.session_epoch {
                        entry.get_mut().session_epoch = session_epoch;
                    }
                    return state;
                }
                if session_epoch < current.session_epoch {
                    return new_state();
                }
                let state = new_state();
                entry.insert(ManagedRuntimeContinuity {
                    runtime_id,
                    session_epoch,
                    state: state.clone(),
                });
                state
            }
            Entry::Vacant(entry) => {
                let state = new_state();
                entry.insert(ManagedRuntimeContinuity {
                    runtime_id,
                    session_epoch,
                    state: state.clone(),
                });
                state
            }
        }
    }

    fn current_managed_runtime_state(
        &self,
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
    ) -> Option<SharedManagedRuntimeState> {
        self.0
            .managed_runtime_states
            .get(&(user_id, machine_id))
            .map(|entry| entry.state.clone())
    }

    pub(super) fn record_full_managed_config_change(
        &self,
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
        config_revision: &str,
    ) -> bool {
        let Some(state) = self.current_managed_runtime_state(user_id, machine_id) else {
            return false;
        };
        let mut state = state.lock().expect("managed runtime state lock poisoned");
        let target_already_applied =
            state.applied_config_revision.as_deref() == Some(config_revision);
        if target_already_applied && state.pending_managed_config_reconcile.is_none() {
            return false;
        }
        if !target_already_applied {
            record_managed_config_reconcile_hint(
                &mut state.pending_managed_config_reconcile,
                ManagedConfigReconcileHint::Full,
            );
        }
        state.runtime_config_epoch = state.runtime_config_epoch.wrapping_add(1);
        true
    }

    pub(super) fn record_patch_managed_config_change(
        &self,
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
        change: ManagedConfigPersistedChange,
    ) -> bool {
        let Some(state) = self.current_managed_runtime_state(user_id, machine_id) else {
            return false;
        };
        let mut state = state.lock().expect("managed runtime state lock poisoned");
        let target_already_applied =
            state.applied_config_revision.as_deref() == Some(change.target_revision.as_str());
        if target_already_applied && state.pending_managed_config_reconcile.is_none() {
            return false;
        }
        if !target_already_applied {
            record_managed_config_reconcile_hint(
                &mut state.pending_managed_config_reconcile,
                ManagedConfigReconcileHint::Dirty {
                    expected_revision: change.expected_revision,
                    target_revision: change.target_revision,
                    instance_ids: change.dirty_instance_ids,
                },
            );
        }
        state.runtime_config_epoch = state.runtime_config_epoch.wrapping_add(1);
        true
    }

    pub(super) fn invalidate_managed_runtime_state(
        &self,
        user_id: UserIdInDb,
        machine_id: uuid::Uuid,
    ) -> bool {
        let Some(state) = self.current_managed_runtime_state(user_id, machine_id) else {
            return false;
        };
        let mut state = state.lock().expect("managed runtime state lock poisoned");
        state.applied_config_revision = None;
        state.applied_config_revision_known = true;
        state.known_runtime_base_revision = None;
        state.pending_managed_config_reconcile = Some(ManagedConfigReconcileHint::Full);
        state.runtime_config_epoch = state.runtime_config_epoch.wrapping_add(1);
        state.runtime_config_cache_epoch = state.runtime_config_cache_epoch.wrapping_add(1);
        true
    }

    fn remove_client_info_map(
        map: &DashMap<uuid::Uuid, ClientInfo>,
        stoken: &StorageToken,
        session_epoch: u64,
    ) -> bool {
        map.remove_if(&stoken.machine_id, |_, v| {
            v.storage_token.client_url == stoken.client_url
                && v.storage_token.user_id == stoken.user_id
                && v.session_epoch == session_epoch
        })
        .is_some()
    }

    fn update_client_info_map(map: &DashMap<uuid::Uuid, ClientInfo>, client_info: &ClientInfo) {
        map.entry(client_info.storage_token.machine_id)
            .and_modify(|e| {
                let same_client = e.storage_token.client_url
                    == client_info.storage_token.client_url
                    && e.storage_token.user_id == client_info.storage_token.user_id;
                let should_replace = if e.session_epoch != client_info.session_epoch {
                    e.session_epoch < client_info.session_epoch
                } else if (same_client && e.authorized != client_info.authorized)
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

    #[cfg(test)]
    pub fn update_client(&self, stoken: StorageToken, report_time: i64, authorized: bool) {
        self.update_session_client(stoken, report_time, authorized, 0);
    }

    pub(super) fn update_session_client(
        &self,
        stoken: StorageToken,
        report_time: i64,
        authorized: bool,
        session_epoch: u64,
    ) {
        let mut continuity = self
            .0
            .managed_runtime_states
            .entry((stoken.user_id, stoken.machine_id))
            .or_insert_with(|| ManagedRuntimeContinuity {
                runtime_id: None,
                session_epoch,
                state: Arc::new(std::sync::Mutex::new(ManagedRuntimeState::default())),
            });
        if session_epoch < continuity.session_epoch {
            return;
        }
        continuity.session_epoch = session_epoch;

        let inner = self.0.user_clients_map.entry(stoken.user_id).or_default();

        let client_info = ClientInfo {
            storage_token: stoken.clone(),
            report_time,
            authorized,
            session_epoch,
        };
        Self::update_client_info_map(&inner, &client_info);
    }

    pub fn remove_client(&self, stoken: &StorageToken) {
        let _ = self.remove_session_client(stoken, 0);
    }

    pub(super) fn remove_session_client(&self, stoken: &StorageToken, session_epoch: u64) -> bool {
        let Some(mut continuity) = self
            .0
            .managed_runtime_states
            .get_mut(&(stoken.user_id, stoken.machine_id))
        else {
            return false;
        };
        if session_epoch < continuity.session_epoch {
            return false;
        }
        continuity.session_epoch = session_epoch;

        let mut removed = false;
        self.0
            .user_clients_map
            .remove_if(&stoken.user_id, |_, set| {
                removed = Self::remove_client_info_map(set, stoken, session_epoch);
                set.is_empty()
            });
        removed
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

    /// List authorized client sessions that belong to a single user only.
    pub fn list_user_client_tokens(&self, user_id: UserIdInDb) -> Vec<StorageToken> {
        self.0
            .user_clients_map
            .get(&user_id)
            .map(|info_map| {
                info_map
                    .iter()
                    .filter(|info| info.value().authorized)
                    .map(|info| info.value().storage_token.clone())
                    .collect()
            })
            .unwrap_or_default()
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
    async fn newer_session_epoch_owns_route_until_it_is_removed() {
        let storage = Storage::new(Db::memory_db().await);
        let machine_id = uuid::Uuid::new_v4();
        let old = make_storage_token(1, machine_id, "tcp://127.0.0.1:1001");
        let current = make_storage_token(1, machine_id, "tcp://127.0.0.1:1002");

        storage.update_session_client(old.clone(), 20, true, 1);
        storage.update_session_client(current.clone(), 20, true, 2);
        storage.update_session_client(old.clone(), 30, true, 1);

        assert!(!storage.0.owns_authorized_session(&old, 1));
        assert!(storage.0.owns_authorized_session(&current, 2));
        assert_eq!(
            storage.get_client_url_by_machine_id(1, &machine_id),
            Some(current.client_url.clone())
        );

        assert!(!storage.remove_session_client(&old, 1));
        assert_eq!(
            storage.get_client_url_by_machine_id(1, &machine_id),
            Some(current.client_url.clone())
        );
        assert!(storage.remove_session_client(&current, 2));
        assert_eq!(storage.get_client_url_by_machine_id(1, &machine_id), None);

        storage.update_session_client(old.clone(), 40, true, 1);
        assert!(!storage.0.owns_authorized_session(&old, 1));
        assert_eq!(storage.get_client_url_by_machine_id(1, &machine_id), None);
    }

    #[tokio::test]
    async fn same_runtime_reuses_state_across_sessions() {
        let storage = Storage::new(Db::memory_db().await);
        let machine_id = uuid::Uuid::new_v4();
        let runtime_id = uuid::Uuid::new_v4();

        let first = storage.bind_managed_runtime_state(1, machine_id, Some(runtime_id), 1);
        {
            let mut state = first.lock().unwrap();
            state.applied_config_revision = Some("rev-a".to_string());
            state.applied_config_revision_known = true;
        }

        let reconnected = storage.bind_managed_runtime_state(1, machine_id, Some(runtime_id), 2);

        assert!(Arc::ptr_eq(&first, &reconnected));
        let state = reconnected.lock().unwrap();
        assert_eq!(state.applied_config_revision.as_deref(), Some("rev-a"));
        assert!(state.applied_config_revision_known);
    }

    #[tokio::test]
    async fn changed_or_missing_runtime_id_starts_with_unknown_state() {
        let storage = Storage::new(Db::memory_db().await);
        let machine_id = uuid::Uuid::new_v4();
        let first =
            storage.bind_managed_runtime_state(1, machine_id, Some(uuid::Uuid::new_v4()), 1);
        {
            let mut state = first.lock().unwrap();
            state.applied_config_revision = Some("rev-a".to_string());
            state.applied_config_revision_known = true;
        }

        let restarted =
            storage.bind_managed_runtime_state(1, machine_id, Some(uuid::Uuid::new_v4()), 2);
        assert!(!Arc::ptr_eq(&first, &restarted));
        assert!(!restarted.lock().unwrap().applied_config_revision_known);

        let legacy = storage.bind_managed_runtime_state(1, machine_id, None, 3);
        assert!(!Arc::ptr_eq(&restarted, &legacy));
        let legacy_reconnected = storage.bind_managed_runtime_state(1, machine_id, None, 4);
        assert!(!Arc::ptr_eq(&legacy, &legacy_reconnected));
        assert!(
            !legacy_reconnected
                .lock()
                .unwrap()
                .applied_config_revision_known
        );
    }

    #[tokio::test]
    async fn stale_session_cannot_replace_current_runtime_state() {
        let storage = Storage::new(Db::memory_db().await);
        let machine_id = uuid::Uuid::new_v4();
        let current_runtime_id = uuid::Uuid::new_v4();
        let current =
            storage.bind_managed_runtime_state(1, machine_id, Some(current_runtime_id), 2);

        let stale =
            storage.bind_managed_runtime_state(1, machine_id, Some(uuid::Uuid::new_v4()), 1);
        assert!(!Arc::ptr_eq(&current, &stale));

        let reconnected =
            storage.bind_managed_runtime_state(1, machine_id, Some(current_runtime_id), 3);
        assert!(Arc::ptr_eq(&current, &reconnected));
    }

    #[tokio::test]
    async fn patch_hint_survives_disconnect_until_same_runtime_reconnects() {
        let storage = Storage::new(Db::memory_db().await);
        let machine_id = uuid::Uuid::new_v4();
        let runtime_id = uuid::Uuid::new_v4();
        let state = storage.bind_managed_runtime_state(1, machine_id, Some(runtime_id), 1);
        {
            let mut state = state.lock().unwrap();
            state.applied_config_revision = Some("rev-a".to_string());
            state.applied_config_revision_known = true;
            state.known_runtime_base_revision = Some("rev-a".to_string());
        }

        assert!(storage.record_patch_managed_config_change(
            1,
            machine_id,
            ManagedConfigPersistedChange {
                expected_revision: "rev-a".to_string(),
                target_revision: "rev-b".to_string(),
                dirty_instance_ids: std::collections::HashSet::from(["instance-a".to_string(),]),
            },
        ));

        let reconnected = storage.bind_managed_runtime_state(1, machine_id, Some(runtime_id), 2);
        let state = reconnected.lock().unwrap();
        assert_eq!(
            state.pending_managed_config_reconcile,
            Some(ManagedConfigReconcileHint::Dirty {
                expected_revision: "rev-a".to_string(),
                target_revision: "rev-b".to_string(),
                instance_ids: std::collections::HashSet::from(["instance-a".to_string(),]),
            })
        );
        assert_eq!(state.runtime_config_epoch, 1);
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
