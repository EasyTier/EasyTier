use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::proto::peer_rpc::{TrustedCredentialPubkey, TrustedCredentialPubkeyProof};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialEntry {
    pubkey: String,
    #[serde(default)]
    secret: String,
    groups: Vec<String>,
    allow_relay: bool,
    allowed_proxy_cidrs: Vec<String>,
    expiry_unix: i64,
    created_at_unix: i64,
}

pub struct CredentialManager {
    credentials: Mutex<HashMap<String, CredentialEntry>>,
    storage_path: Option<PathBuf>,
}

impl CredentialManager {
    pub fn new(storage_path: Option<PathBuf>) -> Self {
        let mgr = CredentialManager {
            credentials: Mutex::new(HashMap::new()),
            storage_path,
        };
        mgr.load_from_disk();
        mgr
    }

    pub fn generate_credential(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
    ) -> (String, String) {
        self.generate_credential_with_id(groups, allow_relay, allowed_proxy_cidrs, ttl, None)
    }

    pub fn generate_credential_with_id(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
        credential_id: Option<String>,
    ) -> (String, String) {
        let mut credentials = self.credentials.lock().unwrap();
        let id = if let Some(id) = credential_id
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
        {
            if let Some(existing) = credentials.get(&id)
                && !existing.secret.is_empty()
            {
                return (id, existing.secret.clone());
            }
            id
        } else {
            uuid::Uuid::new_v4().to_string()
        };

        let (entry, secret) = Self::build_entry(groups, allow_relay, allowed_proxy_cidrs, ttl);
        credentials.insert(id.clone(), entry);
        drop(credentials);
        self.save_to_disk();
        (id, secret)
    }

    fn build_entry(
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
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
            self.save_to_disk();
        }
        removed
    }

    pub fn get_trusted_pubkeys(&self, network_secret: &str) -> Vec<TrustedCredentialPubkeyProof> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        self.credentials
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.expiry_unix > now)
            .map(|e| {
                let credential = TrustedCredentialPubkey {
                    pubkey: Self::decode_pubkey_b64(&e.pubkey).unwrap_or_default(),
                    groups: e.groups.clone(),
                    allow_relay: e.allow_relay,
                    expiry_unix: e.expiry_unix,
                    allowed_proxy_cidrs: e.allowed_proxy_cidrs.clone(),
                };
                TrustedCredentialPubkeyProof::new_signed(credential, network_secret)
            })
            .filter(|e| {
                e.credential
                    .as_ref()
                    .map(|x| !x.pubkey.is_empty())
                    .unwrap_or(false)
            })
            .collect()
    }

    pub fn is_pubkey_trusted(&self, pubkey: &[u8]) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let encoded = BASE64_STANDARD.encode(pubkey);
        self.credentials
            .lock()
            .unwrap()
            .values()
            .any(|e| e.pubkey == encoded && e.expiry_unix > now)
    }

    pub fn list_credentials(&self) -> Vec<crate::proto::api::instance::CredentialInfo> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        self.credentials
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, e)| e.expiry_unix > now)
            .map(|(id, e)| crate::proto::api::instance::CredentialInfo {
                credential_id: id.clone(),
                groups: e.groups.clone(),
                allow_relay: e.allow_relay,
                expiry_unix: e.expiry_unix,
                allowed_proxy_cidrs: e.allowed_proxy_cidrs.clone(),
            })
            .collect()
    }

    fn save_to_disk(&self) {
        let Some(path) = &self.storage_path else {
            return;
        };
        let creds = self.credentials.lock().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*creds)
            && let Err(e) = std::fs::write(path, json)
        {
            tracing::warn!(?e, "failed to save credentials to disk");
        }
    }

    fn load_from_disk(&self) {
        let Some(path) = &self.storage_path else {
            return;
        };
        let Ok(data) = std::fs::read_to_string(path) else {
            return;
        };
        match serde_json::from_str::<HashMap<String, CredentialEntry>>(&data) {
            Ok(loaded) => {
                *self.credentials.lock().unwrap() = loaded;
                tracing::info!("loaded credentials from {}", path.display());
            }
            Err(e) => {
                tracing::warn!(?e, "failed to parse credentials file");
            }
        }
    }

    fn decode_pubkey_b64(s: &str) -> Option<Vec<u8>> {
        let decoded = BASE64_STANDARD.decode(s).ok()?;
        if decoded.len() != 32 {
            return None;
        }
        Some(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_revoke() {
        let mgr = CredentialManager::new(None);
        let (id, secret) = mgr.generate_credential(
            vec!["guest".to_string()],
            false,
            vec![],
            Duration::from_secs(3600),
        );

        assert!(!id.is_empty());
        assert!(!secret.is_empty());
        assert!(uuid::Uuid::parse_str(&id).is_ok());

        let privkey_bytes: [u8; 32] = BASE64_STANDARD.decode(&secret).unwrap().try_into().unwrap();
        let private = StaticSecret::from(privkey_bytes);
        let pubkey_bytes = PublicKey::from(&private).as_bytes().to_vec();
        assert!(mgr.is_pubkey_trusted(&pubkey_bytes));

        let trusted = mgr.get_trusted_pubkeys("sec");
        assert_eq!(trusted.len(), 1);
        assert_eq!(
            trusted[0].credential.as_ref().unwrap().groups,
            vec!["guest".to_string()]
        );

        assert!(mgr.revoke_credential(&id));
        assert!(!mgr.is_pubkey_trusted(&pubkey_bytes));
        assert!(mgr.get_trusted_pubkeys("sec").is_empty());
    }

    #[test]
    fn test_expired_credential() {
        let mgr = CredentialManager::new(None);
        // TTL of 0 seconds - immediately expired
        let (_, secret) = mgr.generate_credential(vec![], false, vec![], Duration::from_secs(0));

        let privkey_bytes: [u8; 32] = BASE64_STANDARD.decode(&secret).unwrap().try_into().unwrap();
        let private = StaticSecret::from(privkey_bytes);
        let pubkey_bytes = PublicKey::from(&private).as_bytes().to_vec();
        assert!(!mgr.is_pubkey_trusted(&pubkey_bytes));
        assert!(mgr.get_trusted_pubkeys("sec").is_empty());
    }

    #[test]
    fn test_list_credentials() {
        let mgr = CredentialManager::new(None);
        mgr.generate_credential(
            vec!["a".to_string()],
            true,
            vec!["10.0.0.0/24".to_string()],
            Duration::from_secs(3600),
        );
        mgr.generate_credential(vec![], false, vec![], Duration::from_secs(3600));

        let list = mgr.list_credentials();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_keypair_validity() {
        // Verify the generated private key can derive the same public key
        let mgr = CredentialManager::new(None);
        let (id, secret) =
            mgr.generate_credential(vec![], false, vec![], Duration::from_secs(3600));

        let privkey_bytes: [u8; 32] = BASE64_STANDARD.decode(&secret).unwrap().try_into().unwrap();
        let private = StaticSecret::from(privkey_bytes);
        let derived_public = PublicKey::from(&private);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
        assert!(mgr.is_pubkey_trusted(derived_public.as_bytes()));
    }

    #[test]
    fn test_revoke_nonexistent() {
        let mgr = CredentialManager::new(None);
        assert!(!mgr.revoke_credential("nonexistent_id"));
    }

    #[test]
    fn test_multiple_credentials_independent() {
        let mgr = CredentialManager::new(None);
        let (id1, secret1) = mgr.generate_credential(
            vec!["group1".to_string()],
            false,
            vec![],
            Duration::from_secs(3600),
        );
        let (_id2, secret2) = mgr.generate_credential(
            vec!["group2".to_string()],
            true,
            vec!["10.0.0.0/8".to_string()],
            Duration::from_secs(3600),
        );

        let sk1: [u8; 32] = BASE64_STANDARD
            .decode(&secret1)
            .unwrap()
            .try_into()
            .unwrap();
        let sk2: [u8; 32] = BASE64_STANDARD
            .decode(&secret2)
            .unwrap()
            .try_into()
            .unwrap();
        let pk1 = PublicKey::from(&StaticSecret::from(sk1))
            .as_bytes()
            .to_vec();
        let pk2 = PublicKey::from(&StaticSecret::from(sk2))
            .as_bytes()
            .to_vec();

        assert!(mgr.is_pubkey_trusted(&pk1));
        assert!(mgr.is_pubkey_trusted(&pk2));

        // Revoke first, second should still be trusted
        mgr.revoke_credential(&id1);
        assert!(!mgr.is_pubkey_trusted(&pk1));
        assert!(mgr.is_pubkey_trusted(&pk2));

        let trusted = mgr.get_trusted_pubkeys("sec");
        assert_eq!(trusted.len(), 1);
        assert_eq!(
            trusted[0].credential.as_ref().unwrap().groups,
            vec!["group2".to_string()]
        );
        assert!(trusted[0].credential.as_ref().unwrap().allow_relay);
        assert_eq!(
            trusted[0].credential.as_ref().unwrap().allowed_proxy_cidrs,
            vec!["10.0.0.0/8".to_string()]
        );
    }

    #[test]
    fn test_trusted_pubkeys_include_metadata() {
        let mgr = CredentialManager::new(None);
        let (_, secret) = mgr.generate_credential(
            vec!["admin".to_string(), "ops".to_string()],
            true,
            vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()],
            Duration::from_secs(7200),
        );

        let trusted = mgr.get_trusted_pubkeys("sec");
        assert_eq!(trusted.len(), 1);
        let tc = &trusted[0];
        assert_eq!(
            tc.credential.as_ref().unwrap().groups,
            vec!["admin".to_string(), "ops".to_string()]
        );
        assert!(tc.credential.as_ref().unwrap().allow_relay);
        assert_eq!(
            tc.credential.as_ref().unwrap().allowed_proxy_cidrs,
            vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()]
        );
        assert!(tc.credential.as_ref().unwrap().expiry_unix > 0);
        assert!(tc.verify_credential_hmac("sec"));
        assert!(
            tc.credential
                .as_ref()
                .map(|x| !x.pubkey.is_empty())
                .unwrap_or(false)
        );

        let sk: [u8; 32] = BASE64_STANDARD.decode(&secret).unwrap().try_into().unwrap();
        let pk = PublicKey::from(&StaticSecret::from(sk)).as_bytes().to_vec();
        assert_eq!(tc.credential.as_ref().unwrap().pubkey, pk);
    }

    #[test]
    fn test_unknown_pubkey_not_trusted() {
        let mgr = CredentialManager::new(None);
        mgr.generate_credential(vec![], false, vec![], Duration::from_secs(3600));

        let random_key = [42u8; 32];
        assert!(!mgr.is_pubkey_trusted(&random_key));
    }

    #[test]
    fn test_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");

        // Create and save
        {
            let mgr = CredentialManager::new(Some(path.clone()));
            mgr.generate_credential(
                vec!["persist_group".to_string()],
                true,
                vec!["10.0.0.0/24".to_string()],
                Duration::from_secs(3600),
            );
            assert_eq!(mgr.list_credentials().len(), 1);
        }

        // Load from disk
        {
            let mgr = CredentialManager::new(Some(path));
            let list = mgr.list_credentials();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].groups, vec!["persist_group".to_string()]);
            assert!(list[0].allow_relay);
        }
    }

    #[test]
    fn test_list_credentials_filters_expired() {
        let mgr = CredentialManager::new(None);
        mgr.generate_credential(vec![], false, vec![], Duration::from_secs(3600));
        mgr.generate_credential(vec![], false, vec![], Duration::from_secs(0)); // expired

        let list = mgr.list_credentials();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_generate_with_specified_id_reuses_existing_result() {
        let mgr = CredentialManager::new(None);
        let fixed_id = "fixed-credential-id".to_string();
        let (id1, secret1) = mgr.generate_credential_with_id(
            vec!["group-a".to_string()],
            false,
            vec!["10.0.0.0/24".to_string()],
            Duration::from_secs(3600),
            Some(fixed_id.clone()),
        );
        let (id2, secret2) = mgr.generate_credential_with_id(
            vec!["group-b".to_string()],
            true,
            vec!["192.168.0.0/16".to_string()],
            Duration::from_secs(7200),
            Some(fixed_id.clone()),
        );

        assert_eq!(id1, fixed_id);
        assert_eq!(id2, fixed_id);
        assert_eq!(secret1, secret2);

        let list = mgr.list_credentials();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].credential_id, fixed_id);
        assert_eq!(list[0].groups, vec!["group-a".to_string()]);
        assert!(!list[0].allow_relay);
        assert_eq!(list[0].allowed_proxy_cidrs, vec!["10.0.0.0/24".to_string()]);
    }
}
