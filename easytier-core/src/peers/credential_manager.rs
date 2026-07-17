use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::proto::peer_rpc::{TrustedCredentialPubkey, TrustedCredentialPubkeyProof};

fn default_true() -> bool {
    true
}

fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CredentialEntry {
    pubkey: String,
    #[serde(default)]
    secret: String,
    groups: Vec<String>,
    allow_relay: bool,
    allowed_proxy_cidrs: Vec<String>,
    #[serde(default = "default_true")]
    reusable: bool,
    expiry_unix: i64,
    created_at_unix: i64,
}

impl CredentialEntry {
    fn is_active_at(&self, now: i64) -> bool {
        self.expiry_unix > now
    }

    fn to_trusted_credential(&self) -> Option<TrustedCredentialPubkey> {
        Some(TrustedCredentialPubkey {
            pubkey: CredentialManager::decode_pubkey_b64(&self.pubkey)?,
            groups: self.groups.clone(),
            allow_relay: self.allow_relay,
            expiry_unix: self.expiry_unix,
            allowed_proxy_cidrs: self.allowed_proxy_cidrs.clone(),
            reusable: Some(self.reusable),
        })
    }

    fn to_credential_info(&self, credential_id: &str) -> CredentialInfo {
        CredentialInfo {
            credential_id: credential_id.to_string(),
            groups: self.groups.clone(),
            allow_relay: self.allow_relay,
            expiry_unix: self.expiry_unix,
            allowed_proxy_cidrs: self.allowed_proxy_cidrs.clone(),
            reusable: Some(self.reusable),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialInfo {
    pub credential_id: String,
    pub groups: Vec<String>,
    pub allow_relay: bool,
    pub expiry_unix: i64,
    pub allowed_proxy_cidrs: Vec<String>,
    pub reusable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedCredential {
    pub credential_id: String,
    pub secret: String,
    pub changed: bool,
}

pub trait CredentialStorage: Send + Sync + 'static {
    fn load(&self) -> anyhow::Result<Option<String>>;
    fn store(&self, serialized_credentials: &str) -> anyhow::Result<()>;
}

pub(crate) struct CredentialManager {
    credentials: Mutex<HashMap<String, CredentialEntry>>,
    storage: Option<Arc<dyn CredentialStorage>>,
    storage_write: Mutex<()>,
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialManager {
    pub fn new() -> Self {
        Self {
            credentials: Mutex::new(HashMap::new()),
            storage: None,
            storage_write: Mutex::new(()),
        }
    }

    pub fn from_storage(storage: Arc<dyn CredentialStorage>) -> Self {
        let credentials = match storage.load() {
            Ok(Some(serialized)) => serde_json::from_str(&serialized).unwrap_or_else(|error| {
                tracing::warn!(?error, "failed to parse stored credentials");
                HashMap::new()
            }),
            Ok(None) => HashMap::new(),
            Err(error) => {
                tracing::warn!(?error, "failed to load stored credentials");
                HashMap::new()
            }
        };
        Self {
            credentials: Mutex::new(credentials),
            storage: Some(storage),
            storage_write: Mutex::new(()),
        }
    }

    pub fn with_entries<R>(&self, f: impl FnOnce(&HashMap<String, CredentialEntry>) -> R) -> R {
        let credentials = self.credentials.lock().unwrap();
        f(&credentials)
    }

    pub fn generate_credential_with_options(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
        credential_id: Option<String>,
        reusable: bool,
    ) -> GeneratedCredential {
        self.remove_expired_credentials();
        self.generate_credential_with_options_after_cleanup(
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            ttl,
            credential_id,
            reusable,
        )
    }

    pub fn generate_credential_with_options_after_cleanup(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
        credential_id: Option<String>,
        reusable: bool,
    ) -> GeneratedCredential {
        let generated = {
            let mut credentials = self.credentials.lock().unwrap();
            let id = if let Some(id) = credential_id
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
            {
                if let Some(existing) = credentials.get(&id)
                    && !existing.secret.is_empty()
                {
                    return GeneratedCredential {
                        credential_id: id,
                        secret: existing.secret.clone(),
                        changed: false,
                    };
                }
                id
            } else {
                uuid::Uuid::new_v4().to_string()
            };

            let (entry, secret) =
                Self::build_entry(groups, allow_relay, allowed_proxy_cidrs, reusable, ttl);
            credentials.insert(id.clone(), entry);
            GeneratedCredential {
                credential_id: id,
                secret,
                changed: true,
            }
        };
        self.persist();
        generated
    }

    fn build_entry(
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        reusable: bool,
        ttl: Duration,
    ) -> (CredentialEntry, String) {
        let private = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&private);
        let pubkey = BASE64_STANDARD.encode(public.as_bytes());
        let secret = BASE64_STANDARD.encode(private.as_bytes());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expiry_unix = now + ttl.as_secs() as i64;

        let entry = CredentialEntry {
            pubkey,
            secret: secret.clone(),
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            reusable,
            expiry_unix,
            created_at_unix: now,
        };
        (entry, secret)
    }

    pub fn revoke_credential(&self, credential_id: &str) -> bool {
        let removed = self
            .credentials
            .lock()
            .unwrap()
            .remove(credential_id)
            .is_some();
        if removed {
            self.persist();
        }
        removed
    }

    pub fn remove_expired_credentials(&self) -> bool {
        self.remove_expired_credentials_at(current_unix_timestamp())
    }

    fn remove_expired_credentials_at(&self, now: i64) -> bool {
        let mut credentials = self.credentials.lock().unwrap();
        let before = credentials.len();
        credentials.retain(|_, entry| entry.is_active_at(now));
        let changed = before != credentials.len();
        drop(credentials);
        if changed {
            self.persist();
        }
        changed
    }

    pub fn get_trusted_pubkeys(&self, network_secret: &str) -> Vec<TrustedCredentialPubkeyProof> {
        let now = current_unix_timestamp();

        self.credentials
            .lock()
            .unwrap()
            .values()
            .filter(|entry| entry.is_active_at(now))
            .filter_map(|entry| {
                entry.to_trusted_credential().map(|credential| {
                    TrustedCredentialPubkeyProof::new_signed(credential, network_secret)
                })
            })
            .collect()
    }

    pub fn is_pubkey_trusted(&self, pubkey: &[u8]) -> bool {
        let now = current_unix_timestamp();

        let encoded = BASE64_STANDARD.encode(pubkey);
        self.credentials
            .lock()
            .unwrap()
            .values()
            .any(|entry| entry.pubkey == encoded && entry.is_active_at(now))
    }

    pub fn list_credentials(&self) -> Vec<CredentialInfo> {
        let now = current_unix_timestamp();

        self.credentials
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, entry)| entry.is_active_at(now))
            .map(|(id, entry)| entry.to_credential_info(id))
            .collect()
    }

    fn decode_pubkey_b64(s: &str) -> Option<Vec<u8>> {
        let decoded = BASE64_STANDARD.decode(s).ok()?;
        if decoded.len() != 32 {
            return None;
        }
        Some(decoded)
    }

    fn persist(&self) {
        let Some(storage) = &self.storage else {
            return;
        };
        let _storage_write = self.storage_write.lock().unwrap();
        let serialized = match self.with_entries(serde_json::to_string_pretty) {
            Ok(serialized) => serialized,
            Err(error) => {
                tracing::warn!(?error, "failed to serialize credentials");
                return;
            }
        };
        if let Err(error) = storage.store(&serialized) {
            tracing::warn!(?error, "failed to store credentials");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl CredentialManager {
        pub(crate) fn generate_credential(
            &self,
            groups: Vec<String>,
            allow_relay: bool,
            allowed_proxy_cidrs: Vec<String>,
            ttl: Duration,
        ) -> GeneratedCredential {
            self.generate_credential_with_options(
                groups,
                allow_relay,
                allowed_proxy_cidrs,
                ttl,
                None,
                true,
            )
        }

        fn generate_credential_with_id(
            &self,
            groups: Vec<String>,
            allow_relay: bool,
            allowed_proxy_cidrs: Vec<String>,
            ttl: Duration,
            credential_id: Option<String>,
        ) -> GeneratedCredential {
            self.generate_credential_with_options(
                groups,
                allow_relay,
                allowed_proxy_cidrs,
                ttl,
                credential_id,
                true,
            )
        }
    }

    #[derive(Default)]
    struct MemoryCredentialStorage {
        serialized: Mutex<Option<String>>,
    }

    impl CredentialStorage for MemoryCredentialStorage {
        fn load(&self) -> anyhow::Result<Option<String>> {
            Ok(self.serialized.lock().unwrap().clone())
        }

        fn store(&self, serialized_credentials: &str) -> anyhow::Result<()> {
            *self.serialized.lock().unwrap() = Some(serialized_credentials.to_owned());
            Ok(())
        }
    }

    #[test]
    fn generate_and_revoke_credential() {
        let mgr = CredentialManager::new();
        let generated = mgr.generate_credential(
            vec!["guest".to_string()],
            false,
            vec![],
            Duration::from_secs(3600),
        );

        assert!(!generated.credential_id.is_empty());
        assert!(!generated.secret.is_empty());
        assert!(generated.changed);
        assert!(uuid::Uuid::parse_str(&generated.credential_id).is_ok());

        let privkey_bytes: [u8; 32] = BASE64_STANDARD
            .decode(&generated.secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = StaticSecret::from(privkey_bytes);
        let pubkey_bytes = PublicKey::from(&private).as_bytes().to_vec();
        assert!(mgr.is_pubkey_trusted(&pubkey_bytes));

        let trusted = mgr.get_trusted_pubkeys("sec");
        assert_eq!(trusted.len(), 1);
        assert_eq!(
            trusted[0].credential.as_ref().unwrap().groups,
            vec!["guest".to_string()]
        );
        assert_eq!(trusted[0].credential.as_ref().unwrap().reusable, Some(true));

        assert!(mgr.revoke_credential(&generated.credential_id));
        assert!(!mgr.is_pubkey_trusted(&pubkey_bytes));
        assert!(mgr.get_trusted_pubkeys("sec").is_empty());
    }

    #[test]
    fn fixed_id_reuses_existing_secret() {
        let mgr = CredentialManager::new();
        let fixed_id = "fixed-credential-id".to_string();
        let first = mgr.generate_credential_with_id(
            vec!["group-a".to_string()],
            false,
            vec!["10.0.0.0/24".to_string()],
            Duration::from_secs(3600),
            Some(fixed_id.clone()),
        );
        let second = mgr.generate_credential_with_id(
            vec!["group-b".to_string()],
            true,
            vec!["192.168.0.0/16".to_string()],
            Duration::from_secs(7200),
            Some(fixed_id.clone()),
        );

        assert_eq!(first.credential_id, fixed_id);
        assert_eq!(second.credential_id, fixed_id);
        assert_eq!(first.secret, second.secret);
        assert!(first.changed);
        assert!(!second.changed);

        let list = mgr.list_credentials();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].credential_id, fixed_id);
        assert_eq!(list[0].groups, vec!["group-a".to_string()]);
        assert!(!list[0].allow_relay);
        assert_eq!(list[0].allowed_proxy_cidrs, vec!["10.0.0.0/24".to_string()]);
        assert_eq!(list[0].reusable, Some(true));
    }

    #[test]
    fn expired_credentials_are_filtered() {
        let mgr = CredentialManager::new();
        mgr.generate_credential(vec![], false, vec![], Duration::from_secs(3600));
        mgr.generate_credential(vec![], false, vec![], Duration::from_secs(0));

        assert_eq!(mgr.list_credentials().len(), 1);
        assert!(mgr.remove_expired_credentials());
        assert_eq!(mgr.list_credentials().len(), 1);
    }

    #[test]
    fn injected_storage_loads_and_persists_mutations() {
        let storage = Arc::new(MemoryCredentialStorage::default());
        let manager = CredentialManager::from_storage(storage.clone());
        let generated =
            manager.generate_credential(vec![], false, vec![], Duration::from_secs(3600));

        let reloaded = CredentialManager::from_storage(storage.clone());
        assert_eq!(
            reloaded.list_credentials()[0].credential_id,
            generated.credential_id
        );

        assert!(manager.revoke_credential(&generated.credential_id));
        let reloaded = CredentialManager::from_storage(storage);
        assert!(reloaded.list_credentials().is_empty());
    }

    #[test]
    fn malformed_storage_starts_with_empty_credentials() {
        let storage = Arc::new(MemoryCredentialStorage {
            serialized: Mutex::new(Some("not json".to_owned())),
        });

        let manager = CredentialManager::from_storage(storage);

        assert!(manager.list_credentials().is_empty());
    }
}
