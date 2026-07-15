#[cfg(test)]
use std::time::Duration;
use std::{path::PathBuf, sync::Arc};

#[cfg(test)]
use easytier_core::peers::credential_manager::CredentialManager as CoreCredentialManager;
use easytier_core::peers::credential_manager::{CredentialInfo, CredentialStorage};

#[cfg(test)]
pub struct CredentialManager {
    core: Arc<CoreCredentialManager>,
}

struct FileCredentialStorage {
    path: PathBuf,
}

impl CredentialStorage for FileCredentialStorage {
    fn load(&self) -> anyhow::Result<Option<String>> {
        let Ok(serialized) = std::fs::read_to_string(&self.path) else {
            return Ok(None);
        };
        tracing::info!("loaded credentials from {}", self.path.display());
        Ok(Some(serialized))
    }

    fn store(&self, serialized_credentials: &str) -> anyhow::Result<()> {
        std::fs::write(&self.path, serialized_credentials)?;
        Ok(())
    }
}

pub(crate) fn runtime_credential_storage(
    path: Option<PathBuf>,
) -> Option<Arc<dyn CredentialStorage>> {
    path.map(|path| Arc::new(FileCredentialStorage { path }) as Arc<dyn CredentialStorage>)
}

#[cfg(test)]
impl CredentialManager {
    pub fn new(storage_path: Option<PathBuf>) -> Self {
        let core = runtime_credential_storage(storage_path).map_or_else(
            CoreCredentialManager::new,
            CoreCredentialManager::from_storage,
        );
        Self {
            core: Arc::new(core),
        }
    }

    pub(crate) fn from_core(core: Arc<CoreCredentialManager>) -> Self {
        Self { core }
    }

    pub fn core(&self) -> Arc<CoreCredentialManager> {
        self.core.clone()
    }

    pub fn generate_credential(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
    ) -> (String, String) {
        self.generate_credential_with_options(
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            ttl,
            None,
            true,
        )
    }

    pub fn generate_credential_with_id(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
        credential_id: Option<String>,
    ) -> (String, String) {
        self.generate_credential_with_options(
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            ttl,
            credential_id,
            true,
        )
    }

    pub fn generate_credential_with_options(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
        credential_id: Option<String>,
        reusable: bool,
    ) -> (String, String) {
        let generated = self.core.generate_credential_with_options(
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            ttl,
            credential_id,
            reusable,
        );
        (generated.credential_id, generated.secret)
    }

    pub fn revoke_credential(&self, credential_id: &str) -> bool {
        self.core.revoke_credential(credential_id)
    }

    pub fn remove_expired_credentials(&self) -> bool {
        self.core.remove_expired_credentials()
    }

    pub fn get_trusted_pubkeys(
        &self,
        network_secret: &str,
    ) -> Vec<crate::proto::peer_rpc::TrustedCredentialPubkeyProof> {
        self.core.get_trusted_pubkeys(network_secret)
    }

    pub fn is_pubkey_trusted(&self, pubkey: &[u8]) -> bool {
        self.core.is_pubkey_trusted(pubkey)
    }

    pub fn list_credentials(&self) -> Vec<crate::proto::api::instance::CredentialInfo> {
        self.core
            .list_credentials()
            .into_iter()
            .map(core_credential_info_to_api)
            .collect()
    }
}

pub(crate) fn core_credential_info_to_api(
    info: CredentialInfo,
) -> crate::proto::api::instance::CredentialInfo {
    crate::proto::api::instance::CredentialInfo {
        credential_id: info.credential_id,
        groups: info.groups,
        allow_relay: info.allow_relay,
        expiry_unix: info.expiry_unix,
        allowed_proxy_cidrs: info.allowed_proxy_cidrs,
        reusable: info.reusable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use x25519_dalek::{PublicKey, StaticSecret};

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
        assert_eq!(trusted[0].credential.as_ref().unwrap().reusable, Some(true));

        assert!(mgr.revoke_credential(&id));
        assert!(!mgr.is_pubkey_trusted(&pubkey_bytes));
        assert!(mgr.get_trusted_pubkeys("sec").is_empty());
    }

    #[test]
    fn test_expired_credential() {
        let mgr = CredentialManager::new(None);
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
        assert!(list.iter().all(|item| item.reusable == Some(true)));
    }

    #[test]
    fn test_keypair_validity() {
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
        assert_eq!(trusted[0].credential.as_ref().unwrap().reusable, Some(true));
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
        assert_eq!(tc.credential.as_ref().unwrap().reusable, Some(true));
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

        {
            let mgr = CredentialManager::new(Some(path));
            let list = mgr.list_credentials();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].groups, vec!["persist_group".to_string()]);
            assert!(list[0].allow_relay);
            assert_eq!(list[0].reusable, Some(true));
        }
    }

    #[test]
    fn test_list_credentials_filters_expired() {
        let mgr = CredentialManager::new(None);
        mgr.generate_credential(vec![], false, vec![], Duration::from_secs(3600));
        mgr.generate_credential(vec![], false, vec![], Duration::from_secs(0));

        let list = mgr.list_credentials();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_remove_expired_credentials_removes_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        let mgr = CredentialManager::new(Some(path.clone()));
        mgr.generate_credential_with_id(
            vec!["active".to_string()],
            false,
            vec![],
            Duration::from_secs(3600),
            Some("active-id".to_string()),
        );
        mgr.generate_credential_with_id(
            vec!["expired".to_string()],
            false,
            vec![],
            Duration::from_secs(0),
            Some("expired-id".to_string()),
        );

        assert!(mgr.remove_expired_credentials());
        assert_eq!(mgr.list_credentials().len(), 1);

        let reloaded = CredentialManager::new(Some(path));
        let list = reloaded.list_credentials();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].credential_id, "active-id");
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
        assert_eq!(list[0].reusable, Some(true));
    }

    #[test]
    fn test_generate_with_specified_id_replaces_expired_existing_result() {
        let mgr = CredentialManager::new(None);
        let fixed_id = "fixed-credential-id".to_string();
        let (id1, secret1) = mgr.generate_credential_with_id(
            vec!["expired".to_string()],
            false,
            vec![],
            Duration::from_secs(0),
            Some(fixed_id.clone()),
        );
        let (id2, secret2) = mgr.generate_credential_with_id(
            vec!["fresh".to_string()],
            true,
            vec!["10.0.0.0/24".to_string()],
            Duration::from_secs(3600),
            Some(fixed_id.clone()),
        );

        assert_eq!(id1, fixed_id);
        assert_eq!(id2, fixed_id);
        assert_ne!(secret1, secret2);

        let list = mgr.list_credentials();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].credential_id, fixed_id);
        assert_eq!(list[0].groups, vec!["fresh".to_string()]);
        assert!(list[0].allow_relay);
        assert_eq!(list[0].allowed_proxy_cidrs, vec!["10.0.0.0/24".to_string()]);
    }

    #[test]
    fn test_generate_non_reusable_credential() {
        let mgr = CredentialManager::new(None);
        let (_id, secret) = mgr.generate_credential_with_options(
            vec!["single".to_string()],
            false,
            vec![],
            Duration::from_secs(3600),
            None,
            false,
        );

        let privkey_bytes: [u8; 32] = BASE64_STANDARD.decode(&secret).unwrap().try_into().unwrap();
        let private = StaticSecret::from(privkey_bytes);
        let pubkey_bytes = PublicKey::from(&private).as_bytes().to_vec();

        let listed = mgr.list_credentials();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].reusable, Some(false));
        assert!(mgr.is_pubkey_trusted(&pubkey_bytes));

        let trusted = mgr.get_trusted_pubkeys("sec");
        assert_eq!(trusted.len(), 1);
        assert_eq!(
            trusted[0].credential.as_ref().unwrap().reusable,
            Some(false)
        );
    }

    #[test]
    fn test_load_old_credentials_default_to_reusable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy-creds.json");
        std::fs::write(
            &path,
            r#"{
  "legacy-id": {
    "pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "secret": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    "groups": ["legacy"],
    "allow_relay": false,
    "allowed_proxy_cidrs": [],
    "expiry_unix": 4102444800,
    "created_at_unix": 1700000000
  }
}"#,
        )
        .unwrap();

        let mgr = CredentialManager::new(Some(path));
        let list = mgr.list_credentials();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].credential_id, "legacy-id");
        assert_eq!(list[0].reusable, Some(true));
    }
}
