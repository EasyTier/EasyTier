use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    config::toml::ManagedCredentialConfig,
    proto::peer_rpc::{TrustedCredentialPubkey, TrustedCredentialPubkeyProof},
};

fn default_true() -> bool {
    true
}

fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[derive(Debug, Clone)]
pub struct CredentialCreateOptions {
    pub groups: Vec<String>,
    pub allow_relay: bool,
    pub allowed_proxy_cidrs: Vec<String>,
    pub ttl: Duration,
    pub credential_id: Option<String>,
    pub reusable: bool,
}

#[derive(Debug, Clone)]
pub struct CredentialUpsertOptions {
    pub credential_id: String,
    pub credential_secret: String,
    pub groups: Vec<String>,
    pub allow_relay: bool,
    pub allowed_proxy_cidrs: Vec<String>,
    pub expiry_unix: i64,
    pub reusable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
            public_key_fingerprint: CredentialManager::public_key_fingerprint(&self.pubkey)
                .unwrap_or_default(),
        }
    }

    fn from_managed(entry: &ManagedCredentialConfig) -> Result<Self, String> {
        let credential_id = entry.credential_id.trim();
        let private_bytes: [u8; 32] = BASE64_STANDARD
            .decode(entry.credential_secret.trim())
            .map_err(|_| format!("credential_secret for {credential_id} must be base64"))?
            .try_into()
            .map_err(|_| format!("credential_secret for {credential_id} must contain 32 bytes"))?;
        let private = StaticSecret::from(private_bytes);
        let mut allowed_proxy_cidrs = Vec::with_capacity(entry.allowed_proxy_cidrs.len());
        for cidr in &entry.allowed_proxy_cidrs {
            let cidr = cidr.trim();
            cidr.parse::<cidr::IpCidr>()
                .map_err(|_| format!("invalid allowed_proxy_cidr for {credential_id}: {cidr}"))?;
            allowed_proxy_cidrs.push(cidr.to_owned());
        }
        Ok(Self {
            pubkey: BASE64_STANDARD.encode(PublicKey::from(&private).as_bytes()),
            secret: BASE64_STANDARD.encode(private.as_bytes()),
            groups: entry.groups.clone(),
            allow_relay: entry.allow_relay,
            allowed_proxy_cidrs,
            reusable: entry.reusable,
            expiry_unix: entry.expiry_unix,
            created_at_unix: 0,
        })
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
    pub public_key_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedCredential {
    pub credential_id: String,
    pub secret: String,
    pub expiry_unix: i64,
    pub changed: bool,
}

pub trait CredentialStorage: Send + Sync + 'static {
    fn load(&self) -> anyhow::Result<Option<String>>;

    /// Atomically replaces the previously committed credential snapshot.
    /// Returning an error must leave that snapshot readable.
    fn store(&self, serialized_credentials: &str) -> anyhow::Result<()>;
}

#[derive(Default)]
struct CredentialState {
    base: HashMap<String, CredentialEntry>,
    managed: HashMap<String, CredentialEntry>,
    ephemeral: HashMap<uuid::Uuid, CredentialEntry>,
}

pub(crate) struct CredentialManager {
    state: Mutex<CredentialState>,
    storage: Option<Arc<dyn CredentialStorage>>,
    storage_load_error: Option<String>,
}

/// A validated managed credential replacement awaiting installation.
#[cfg(feature = "web-client")]
pub(crate) struct ManagedCredentialReplacement<'a> {
    manager: &'a CredentialManager,
    changed: bool,
    replacement: HashMap<String, CredentialEntry>,
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialManager {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(CredentialState::default()),
            storage: None,
            storage_load_error: None,
        }
    }

    pub fn from_storage(storage: Arc<dyn CredentialStorage>) -> Self {
        let loaded = match storage.load() {
            Ok(Some(serialized)) => serde_json::from_str(&serialized).map_err(anyhow::Error::from),
            Ok(None) => Ok(HashMap::new()),
            Err(error) => Err(error),
        };
        let (base, storage_load_error) = match loaded {
            Ok(base) => (base, None),
            Err(error) => {
                tracing::error!(?error, "credential storage is unavailable");
                (HashMap::new(), Some(error.to_string()))
            }
        };
        Self {
            state: Mutex::new(CredentialState {
                base,
                ..Default::default()
            }),
            storage: Some(storage),
            storage_load_error,
        }
    }

    pub fn generate_credential_with_options(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
        credential_id: Option<String>,
        reusable: bool,
    ) -> Result<GeneratedCredential, String> {
        self.ensure_storage_available()
            .map_err(|error| error.to_string())?;
        let mut state = self.state.lock().unwrap();
        let now = current_unix_timestamp();
        let mut updated = state.base.clone();
        updated.retain(|_, entry| entry.is_active_at(now));
        let id = if let Some(id) = credential_id
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
        {
            if state.managed.contains_key(&id) {
                return Err(format!("credential_id {id} is managed by configuration"));
            }
            if let Some(existing) = updated.get(&id)
                && !existing.secret.is_empty()
            {
                return Ok(GeneratedCredential {
                    credential_id: id,
                    secret: existing.secret.clone(),
                    expiry_unix: existing.expiry_unix,
                    changed: false,
                });
            }
            id
        } else {
            loop {
                let id = uuid::Uuid::new_v4().to_string();
                if !updated.contains_key(&id) && !state.managed.contains_key(&id) {
                    break id;
                }
            }
        };

        let (entry, secret) = loop {
            let generated = Self::build_entry(
                groups.clone(),
                allow_relay,
                allowed_proxy_cidrs.clone(),
                reusable,
                ttl,
            );
            let public_key_in_use = updated
                .values()
                .chain(state.managed.values())
                .chain(state.ephemeral.values())
                .any(|existing| existing.pubkey == generated.0.pubkey);
            if !public_key_in_use {
                break generated;
            }
        };
        let expiry_unix = entry.expiry_unix;
        updated.insert(id.clone(), entry);
        self.store_base(&updated)
            .map_err(|error| format!("failed to store credentials: {error}"))?;
        state.base = updated;
        Ok(GeneratedCredential {
            credential_id: id,
            secret,
            expiry_unix,
            changed: true,
        })
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

    pub fn revoke_credential(&self, credential_id: &str) -> Result<bool, String> {
        self.ensure_storage_available()
            .map_err(|error| error.to_string())?;
        let mut state = self.state.lock().unwrap();
        if !state.base.contains_key(credential_id) {
            return Ok(false);
        }
        let mut updated = state.base.clone();
        updated.remove(credential_id);
        self.store_base(&updated)
            .map_err(|error| format!("failed to store credentials: {error}"))?;
        state.base = updated;
        Ok(true)
    }

    pub fn register_ephemeral_credential(
        &self,
        public_key: [u8; 32],
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        reusable: bool,
    ) -> Result<uuid::Uuid, String> {
        let entry = CredentialEntry {
            pubkey: BASE64_STANDARD.encode(public_key),
            secret: String::new(),
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            reusable,
            expiry_unix: i64::MAX,
            created_at_unix: current_unix_timestamp(),
        };

        let mut state = self.state.lock().unwrap();
        if state
            .base
            .values()
            .chain(state.managed.values())
            .any(|existing| existing.pubkey == entry.pubkey)
            || state
                .ephemeral
                .values()
                .any(|existing| existing.pubkey == entry.pubkey)
        {
            return Err("credential public key is already registered".to_owned());
        }

        let credential_id = uuid::Uuid::new_v4();
        state.ephemeral.insert(credential_id, entry);
        Ok(credential_id)
    }

    pub fn update_ephemeral_credential_groups(
        &self,
        credential_id: uuid::Uuid,
        groups: Vec<String>,
    ) -> Option<bool> {
        let mut state = self.state.lock().unwrap();
        let credential = state.ephemeral.get_mut(&credential_id)?;
        if credential.groups == groups {
            return Some(false);
        }
        credential.groups = groups;
        Some(true)
    }

    pub fn revoke_ephemeral_credential(&self, credential_id: uuid::Uuid) -> bool {
        self.state
            .lock()
            .unwrap()
            .ephemeral
            .remove(&credential_id)
            .is_some()
    }

    pub fn upsert_credential(&self, options: CredentialUpsertOptions) -> Result<bool, String> {
        let CredentialUpsertOptions {
            credential_id,
            credential_secret,
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            expiry_unix,
            reusable,
        } = options;
        let credential_id = credential_id.trim().to_string();
        if credential_id.is_empty() {
            return Err("credential_id must not be empty".to_string());
        }
        if expiry_unix <= current_unix_timestamp() {
            return Err("expiry_unix must be in the future".to_string());
        }

        let private_bytes: [u8; 32] = BASE64_STANDARD
            .decode(credential_secret.trim())
            .map_err(|_| "credential_secret must be base64".to_string())?
            .try_into()
            .map_err(|_| "credential_secret must contain 32 bytes".to_string())?;
        let private = StaticSecret::from(private_bytes);
        let entry = CredentialEntry {
            pubkey: BASE64_STANDARD.encode(PublicKey::from(&private).as_bytes()),
            secret: BASE64_STANDARD.encode(private.as_bytes()),
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            reusable,
            expiry_unix,
            created_at_unix: current_unix_timestamp(),
        };

        self.ensure_storage_available()
            .map_err(|error| error.to_string())?;
        let mut state = self.state.lock().unwrap();
        if state.managed.contains_key(&credential_id) {
            return Err(format!(
                "credential_id {credential_id} is managed by configuration"
            ));
        }
        if state
            .base
            .iter()
            .chain(state.managed.iter())
            .any(|(existing_id, existing)| {
                existing_id != &credential_id && existing.pubkey == entry.pubkey
            })
        {
            return Err("credential_secret is already used by another credential_id".to_string());
        }
        if state
            .ephemeral
            .values()
            .any(|existing| existing.pubkey == entry.pubkey)
        {
            return Err("credential public key is already registered".to_owned());
        }
        let changed = state.base.get(&credential_id).is_none_or(|existing| {
            existing.secret != entry.secret
                || existing.pubkey != entry.pubkey
                || existing.groups != entry.groups
                || existing.allow_relay != entry.allow_relay
                || existing.allowed_proxy_cidrs != entry.allowed_proxy_cidrs
                || existing.reusable != entry.reusable
                || existing.expiry_unix != entry.expiry_unix
        });
        if !changed {
            return Ok(false);
        }

        let mut updated = state.base.clone();
        updated.insert(credential_id, entry);
        self.store_base(&updated)
            .map_err(|error| format!("failed to store credentials: {error}"))?;
        state.base = updated;
        Ok(true)
    }

    pub fn remove_expired_credentials(&self) -> bool {
        self.remove_expired_credentials_at(current_unix_timestamp())
    }

    fn remove_expired_credentials_at(&self, now: i64) -> bool {
        let mut state = self.state.lock().unwrap();
        let mut updated = state.base.clone();
        updated.retain(|_, entry| entry.is_active_at(now));
        if updated == state.base {
            return false;
        }
        if let Err(error) = self.store_base(&updated) {
            tracing::warn!(?error, "failed to remove expired credentials");
            return false;
        }
        state.base = updated;
        true
    }

    pub fn get_trusted_pubkeys(&self, network_secret: &str) -> Vec<TrustedCredentialPubkeyProof> {
        let now = current_unix_timestamp();
        let to_proof = |entry: &CredentialEntry| {
            entry.to_trusted_credential().map(|credential| {
                TrustedCredentialPubkeyProof::new_signed(credential, network_secret)
            })
        };
        let state = self.state.lock().unwrap();
        let mut trusted = state
            .base
            .values()
            .chain(state.managed.values())
            .filter(|entry| entry.is_active_at(now))
            .filter_map(to_proof)
            .collect::<Vec<_>>();
        trusted.extend(state.ephemeral.values().filter_map(to_proof));
        trusted
    }

    pub fn is_pubkey_trusted(&self, pubkey: &[u8]) -> bool {
        let now = current_unix_timestamp();
        let encoded = BASE64_STANDARD.encode(pubkey);
        let state = self.state.lock().unwrap();
        state
            .base
            .values()
            .chain(state.managed.values())
            .any(|entry| entry.pubkey == encoded && entry.is_active_at(now))
            || state
                .ephemeral
                .values()
                .any(|entry| entry.pubkey == encoded)
    }

    pub fn list_credentials(&self) -> Vec<CredentialInfo> {
        let now = current_unix_timestamp();

        let state = self.state.lock().unwrap();
        let mut credentials = state
            .base
            .iter()
            .chain(state.managed.iter())
            .filter(|(_, entry)| entry.is_active_at(now))
            .map(|(id, entry)| entry.to_credential_info(id))
            .collect::<Vec<_>>();
        credentials.sort_unstable_by(|left, right| left.credential_id.cmp(&right.credential_id));
        credentials
    }

    pub fn install_initial_managed_credentials(
        &self,
        credentials: &[ManagedCredentialConfig],
    ) -> Result<(), String> {
        self.ensure_storage_available()
            .map_err(|error| error.to_string())?;
        let replacement = Self::build_managed_entries(credentials)?;
        let mut state = self.state.lock().unwrap();
        Self::validate_managed_conflicts(&state, &replacement)?;
        state.managed = replacement;
        Ok(())
    }

    /// Fallible checks for a managed credential replacement (secret parsing,
    /// duplicate IDs/keys, conflicts with base/ephemeral credentials). Must
    /// run before the candidate is persisted so a rejected patch never
    /// reaches disk.
    #[cfg(feature = "web-client")]
    pub fn validate_managed_credentials(
        &self,
        credentials: &[ManagedCredentialConfig],
    ) -> Result<ManagedCredentialReplacement<'_>, String> {
        let replacement = Self::build_managed_entries(credentials)?;
        let state = self.state.lock().unwrap();
        Self::validate_managed_conflicts(&state, &replacement)?;
        Ok(ManagedCredentialReplacement {
            manager: self,
            changed: state.managed != replacement,
            replacement,
        })
    }

    /// Installs an already validated replacement. The caller must have run
    /// [`Self::validate_managed_credentials`] first; see the transaction
    /// comment in `apply_config_patch` for the accepted race windows between
    /// the two calls.
    #[cfg(feature = "web-client")]
    pub fn install_managed_credentials(replacement: ManagedCredentialReplacement<'_>) -> bool {
        if !replacement.changed {
            return false;
        }
        let mut state = replacement.manager.state.lock().unwrap();
        state.managed = replacement.replacement;
        true
    }

    fn build_managed_entries(
        credentials: &[ManagedCredentialConfig],
    ) -> Result<HashMap<String, CredentialEntry>, String> {
        let mut entries = HashMap::with_capacity(credentials.len());
        let mut public_keys = HashSet::with_capacity(credentials.len());
        for credential in credentials {
            let credential_id = credential.credential_id.trim().to_owned();
            if credential_id.is_empty() {
                return Err("credential_id must not be empty".to_owned());
            }
            let entry = CredentialEntry::from_managed(credential)?;
            if !public_keys.insert(entry.pubkey.clone()) {
                return Err("credential_secret is assigned to multiple credential IDs".to_owned());
            }
            if entries.insert(credential_id.clone(), entry).is_some() {
                return Err(format!("duplicate managed credential_id: {credential_id}"));
            }
        }
        Ok(entries)
    }

    fn validate_managed_conflicts(
        state: &CredentialState,
        replacement: &HashMap<String, CredentialEntry>,
    ) -> Result<(), String> {
        if let Some(credential_id) = replacement.keys().find(|id| state.base.contains_key(*id)) {
            return Err(format!(
                "credential_id {credential_id} is already owned by the credential file"
            ));
        }
        if replacement.values().any(|entry| {
            state
                .base
                .values()
                .chain(state.ephemeral.values())
                .any(|existing| existing.pubkey == entry.pubkey)
        }) {
            return Err("credential public key is already registered".to_owned());
        }
        Ok(())
    }

    fn decode_pubkey_b64(s: &str) -> Option<Vec<u8>> {
        let decoded = BASE64_STANDARD.decode(s).ok()?;
        if decoded.len() != 32 {
            return None;
        }
        Some(decoded)
    }

    fn public_key_fingerprint(pubkey: &str) -> Option<String> {
        let decoded = Self::decode_pubkey_b64(pubkey)?;
        Some(
            Sha256::digest(decoded)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        )
    }

    fn ensure_storage_available(&self) -> anyhow::Result<()> {
        if let Some(error) = &self.storage_load_error {
            anyhow::bail!("credential storage is unavailable: {error}");
        }
        Ok(())
    }

    fn store_base(&self, base: &HashMap<String, CredentialEntry>) -> anyhow::Result<()> {
        self.ensure_storage_available()?;
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        storage.store(&serde_json::to_string_pretty(base)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed_credential(
        credential_id: &str,
        secret_byte: u8,
        expiry_unix: i64,
    ) -> ManagedCredentialConfig {
        ManagedCredentialConfig {
            credential_id: credential_id.to_owned(),
            credential_secret: BASE64_STANDARD.encode([secret_byte; 32]),
            groups: vec!["ops".to_owned()],
            allow_relay: false,
            allowed_proxy_cidrs: vec!["10.0.0.0/24".to_owned()],
            expiry_unix,
            reusable: true,
        }
    }

    #[test]
    fn managed_credential_trims_allowed_proxy_cidrs() {
        let mut credential = managed_credential("managed", 1, i64::MAX);
        credential.allowed_proxy_cidrs = vec![" 10.0.0.0/24 ".to_owned()];

        let entry = CredentialEntry::from_managed(&credential).unwrap();

        assert_eq!(entry.allowed_proxy_cidrs, ["10.0.0.0/24"]);
    }

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
            .unwrap()
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
            .unwrap()
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

    struct FailOnceCredentialStorage {
        serialized: Mutex<Option<String>>,
        fail_next_store: Mutex<bool>,
    }

    impl Default for FailOnceCredentialStorage {
        fn default() -> Self {
            Self {
                serialized: Mutex::new(None),
                fail_next_store: Mutex::new(true),
            }
        }
    }

    impl CredentialStorage for FailOnceCredentialStorage {
        fn load(&self) -> anyhow::Result<Option<String>> {
            Ok(self.serialized.lock().unwrap().clone())
        }

        fn store(&self, serialized_credentials: &str) -> anyhow::Result<()> {
            let mut fail_next_store = self.fail_next_store.lock().unwrap();
            if *fail_next_store {
                *fail_next_store = false;
                anyhow::bail!("injected credential storage failure");
            }
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
        assert!(generated.expiry_unix > current_unix_timestamp());
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

        assert!(mgr.revoke_credential(&generated.credential_id).unwrap());
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
        assert_eq!(list[0].public_key_fingerprint.len(), 64);
    }

    #[test]
    fn upsert_credential_preserves_key_attributes_and_storage() {
        let source = CredentialManager::new();
        let generated = source
            .generate_credential_with_options(
                vec!["users".to_string()],
                false,
                vec!["10.0.0.0/8".to_string()],
                Duration::from_secs(3600),
                Some("shared-id".to_string()),
                false,
            )
            .unwrap();
        let source_info = source.list_credentials().remove(0);
        let options = CredentialUpsertOptions {
            credential_id: generated.credential_id,
            credential_secret: generated.secret,
            groups: source_info.groups.clone(),
            allow_relay: source_info.allow_relay,
            allowed_proxy_cidrs: source_info.allowed_proxy_cidrs.clone(),
            expiry_unix: source_info.expiry_unix,
            reusable: source_info.reusable.unwrap(),
        };

        let storage = Arc::new(MemoryCredentialStorage::default());
        let target = CredentialManager::from_storage(storage.clone());
        assert!(target.upsert_credential(options.clone()).unwrap());
        assert!(!target.upsert_credential(options).unwrap());
        assert_eq!(target.list_credentials(), vec![source_info.clone()]);
        assert_eq!(
            CredentialManager::from_storage(storage).list_credentials(),
            vec![source_info]
        );
    }

    #[test]
    fn upsert_credential_can_retry_after_storage_failure() {
        let source = CredentialManager::new();
        let generated =
            source.generate_credential(vec![], false, vec![], Duration::from_secs(3600));
        let options = CredentialUpsertOptions {
            credential_id: generated.credential_id,
            credential_secret: generated.secret,
            groups: vec!["users".to_string()],
            allow_relay: false,
            allowed_proxy_cidrs: vec![],
            expiry_unix: generated.expiry_unix,
            reusable: true,
        };

        let storage = Arc::new(FailOnceCredentialStorage::default());
        let target = CredentialManager::from_storage(storage.clone());
        assert!(target.upsert_credential(options.clone()).is_err());
        assert!(target.list_credentials().is_empty());

        assert!(target.upsert_credential(options).unwrap());
        assert_eq!(target.list_credentials().len(), 1);
        assert_eq!(
            CredentialManager::from_storage(storage)
                .list_credentials()
                .len(),
            1
        );
    }

    #[test]
    fn upsert_credential_rejects_public_key_assigned_to_another_id() {
        let source = CredentialManager::new();
        let generated =
            source.generate_credential(vec![], false, vec![], Duration::from_secs(3600));
        let options = CredentialUpsertOptions {
            credential_id: "original-id".to_string(),
            credential_secret: generated.secret,
            groups: vec!["users".to_string()],
            allow_relay: false,
            allowed_proxy_cidrs: vec![],
            expiry_unix: generated.expiry_unix,
            reusable: true,
        };

        let target = CredentialManager::new();
        assert!(target.upsert_credential(options.clone()).unwrap());

        let duplicate = CredentialUpsertOptions {
            credential_id: "duplicate-id".to_string(),
            groups: vec!["admins".to_string()],
            ..options
        };
        assert_eq!(
            target.upsert_credential(duplicate).unwrap_err(),
            "credential_secret is already used by another credential_id"
        );

        let credentials = target.list_credentials();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].credential_id, "original-id");
        assert_eq!(credentials[0].groups, vec!["users".to_string()]);
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

        assert!(manager.revoke_credential(&generated.credential_id).unwrap());
        let reloaded = CredentialManager::from_storage(storage);
        assert!(reloaded.list_credentials().is_empty());
    }

    #[test]
    fn malformed_storage_is_fail_closed() {
        let storage = Arc::new(MemoryCredentialStorage {
            serialized: Mutex::new(Some("not json".to_owned())),
        });

        let manager = CredentialManager::from_storage(storage);

        assert!(manager.list_credentials().is_empty());
        assert!(manager.install_initial_managed_credentials(&[]).is_err());
    }

    #[test]
    fn ephemeral_credentials_are_trusted_but_not_persisted_or_listed() {
        let storage = Arc::new(MemoryCredentialStorage::default());
        let manager = CredentialManager::from_storage(storage.clone());
        let private = StaticSecret::from([7u8; 32]);
        let public = *PublicKey::from(&private).as_bytes();

        let credential_id = manager
            .register_ephemeral_credential(public, vec!["ops".to_owned()], false, Vec::new(), false)
            .unwrap();

        assert!(manager.is_pubkey_trusted(&public));
        let trusted = manager.get_trusted_pubkeys("network-secret");
        assert_eq!(trusted.len(), 1);
        let credential = trusted[0].credential.as_ref().unwrap();
        assert_eq!(credential.pubkey, public);
        assert_eq!(credential.groups, ["ops"]);
        assert!(!credential.allow_relay);
        assert!(credential.allowed_proxy_cidrs.is_empty());
        assert_eq!(credential.reusable, Some(false));
        assert!(manager.list_credentials().is_empty());
        assert!(storage.serialized.lock().unwrap().is_none());

        assert!(manager.revoke_ephemeral_credential(credential_id));
        assert!(!manager.is_pubkey_trusted(&public));
        assert!(manager.get_trusted_pubkeys("network-secret").is_empty());
        assert!(storage.serialized.lock().unwrap().is_none());
    }

    #[cfg(feature = "web-client")]
    #[test]
    fn managed_credentials_work_without_base_storage_and_expire_in_place() {
        let manager = CredentialManager::new();
        let active = managed_credential("active", 1, current_unix_timestamp() + 60);
        let expired = managed_credential("expired", 2, current_unix_timestamp() - 1);

        manager
            .install_initial_managed_credentials(&[active.clone(), expired])
            .unwrap();

        assert_eq!(manager.list_credentials().len(), 1);
        assert_eq!(manager.list_credentials()[0].credential_id, "active");
        let private_bytes: [u8; 32] = BASE64_STANDARD
            .decode(active.credential_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let public = PublicKey::from(&StaticSecret::from(private_bytes));
        assert!(manager.is_pubkey_trusted(public.as_bytes()));

        let replacement = manager.validate_managed_credentials(&[]).unwrap();
        assert!(replacement.changed);
        assert!(CredentialManager::install_managed_credentials(replacement));
        assert!(manager.list_credentials().is_empty());
    }

    #[cfg(feature = "web-client")]
    #[test]
    fn managed_and_base_credentials_must_be_disjoint() {
        let manager = CredentialManager::new();
        manager
            .install_initial_managed_credentials(&[managed_credential(
                "managed",
                3,
                current_unix_timestamp() + 60,
            )])
            .unwrap();

        let error = manager
            .generate_credential_with_options(
                Vec::new(),
                false,
                Vec::new(),
                Duration::from_secs(60),
                Some("managed".to_owned()),
                true,
            )
            .unwrap_err();
        assert!(error.contains("managed by configuration"));

        let generated =
            manager.generate_credential(Vec::new(), false, Vec::new(), Duration::from_secs(60));
        let conflicting = ManagedCredentialConfig {
            credential_id: "other".to_owned(),
            credential_secret: generated.secret,
            ..managed_credential("other", 4, current_unix_timestamp() + 60)
        };
        let error = manager
            .validate_managed_credentials(&[conflicting])
            .err()
            .unwrap();
        assert_eq!(error, "credential public key is already registered");
        // The rejected replacement must not have touched existing state.
        assert!(
            manager
                .list_credentials()
                .iter()
                .any(|info| info.credential_id == "managed")
        );
    }
}
