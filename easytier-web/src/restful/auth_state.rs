use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::db::UserIdInDb;
use base64::Engine as _;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use dashmap::DashMap;
use rand::RngCore;

use super::users::Backend;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(15);
pub const BEARER_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const OIDC_STATE_TTL: Duration = Duration::from_secs(5 * 60);
pub const CAPTCHA_CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenContext {
    pub user_id: UserIdInDb,
    pub token: String,
    pub issued_at: Instant,
    pub expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BearerTokenEntry {
    context: TokenContext,
    revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveTokenFailure {
    Missing,
    Expired,
    Revoked,
}

#[derive(Debug)]
struct BearerTokenStoreInner {
    tokens: DashMap<String, BearerTokenEntry>,
    user_tokens: DashMap<UserIdInDb, DashMap<String, ()>>,
    backend: Backend,
    ttl: Duration,
}

#[derive(Debug, Clone)]
/// 仅在当前进程内保存 opaque bearer token；应用重启后 store 会清空，旧 token 全部失效。
///
/// ⚠️ 警告：当前实现不支持多实例部署或滚动升级。
pub struct BearerTokenStore(Arc<BearerTokenStoreInner>);

impl BearerTokenStore {
    pub fn new(backend: Backend) -> Self {
        Self::with_ttl_and_cleanup_interval(backend, BEARER_TOKEN_TTL, CLEANUP_INTERVAL)
    }

    pub(crate) fn with_ttl_and_cleanup_interval(
        backend: Backend,
        ttl: Duration,
        cleanup_interval: Duration,
    ) -> Self {
        let store = Self(Arc::new(BearerTokenStoreInner {
            tokens: DashMap::new(),
            user_tokens: DashMap::new(),
            backend,
            ttl,
        }));
        store.spawn_cleanup_loop(cleanup_interval);
        store
    }

    fn spawn_cleanup_loop(&self, cleanup_interval: Duration) {
        let inner = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(cleanup_interval).await;
                let Some(inner) = inner.upgrade() else {
                    break;
                };
                let store = BearerTokenStore(inner);
                store.purge_expired_tokens();
            }
        });
    }

    pub fn issue_token(&self, user_id: UserIdInDb) -> String {
        loop {
            let mut raw = [0_u8; 32];
            rand::thread_rng().fill_bytes(&mut raw);
            let token = BASE64_URL_SAFE_NO_PAD.encode(raw);
            if !self.0.tokens.contains_key(&token) {
                self.insert(token.clone(), user_id);
                return token;
            }
        }
    }

    pub fn insert(&self, token: impl Into<String>, user_id: UserIdInDb) -> TokenContext {
        let token = token.into();
        self.remove(&token);
        let issued_at = Instant::now();
        let context = TokenContext {
            user_id,
            token: token.clone(),
            issued_at,
            expires_at: issued_at + self.0.ttl,
        };

        self.tokens_for_user(user_id).insert(token.clone(), ());
        self.0.tokens.insert(
            token,
            BearerTokenEntry {
                context: context.clone(),
                revoked: false,
            },
        );
        context
    }

    pub fn get(&self, token: &str) -> Option<TokenContext> {
        let entry = self.0.tokens.get(token).map(|entry| entry.clone())?;
        if Self::is_expired(entry.context.expires_at) {
            self.remove(token);
            return None;
        }
        Some(entry.context)
    }

    pub fn resolve_token(&self, token: &str) -> Option<TokenContext> {
        self.resolve_token_detailed(token).ok()
    }

    pub fn resolve_token_detailed(&self, token: &str) -> Result<TokenContext, ResolveTokenFailure> {
        let entry = self
            .0
            .tokens
            .get(token)
            .map(|entry| entry.clone())
            .ok_or(ResolveTokenFailure::Missing)?;

        if Self::is_expired(entry.context.expires_at) {
            self.remove(token);
            return Err(ResolveTokenFailure::Expired);
        }

        if entry.revoked {
            return Err(ResolveTokenFailure::Revoked);
        }

        Ok(entry.context)
    }

    pub fn revoke_token(&self, token: &str) -> bool {
        let Some(mut entry) = self.0.tokens.get_mut(token) else {
            return false;
        };

        if Self::is_expired(entry.context.expires_at) {
            drop(entry);
            self.remove(token);
            return false;
        }

        if entry.revoked {
            return false;
        }

        entry.revoked = true;
        true
    }

    pub fn revoke_all_tokens_for_user(&self, user_id: UserIdInDb) -> usize {
        let Some(tokens) = self.0.user_tokens.get(&user_id) else {
            return 0;
        };

        let token_keys = tokens
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        drop(tokens);

        token_keys
            .into_iter()
            .filter(|token| self.revoke_token(token))
            .count()
    }

    pub fn revoke_user_tokens(&self, user_id: UserIdInDb) -> usize {
        self.revoke_all_tokens_for_user(user_id)
    }

    pub fn remove(&self, token: &str) -> Option<TokenContext> {
        let (_, entry) = self.0.tokens.remove(token)?;
        self.0
            .user_tokens
            .remove_if(&entry.context.user_id, |_, tokens| {
                tokens.remove(token);
                tokens.is_empty()
            });
        Some(entry.context)
    }

    pub fn remove_many<I, K>(&self, tokens: I) -> usize
    where
        I: IntoIterator<Item = K>,
        K: AsRef<str>,
    {
        tokens
            .into_iter()
            .filter(|token| self.remove(token.as_ref()).is_some())
            .count()
    }

    pub fn purge_expired_tokens(&self) -> usize {
        let expired_tokens = self
            .0
            .tokens
            .iter()
            .filter_map(|entry| {
                Self::is_expired(entry.context.expires_at).then(|| entry.key().clone())
            })
            .collect::<Vec<_>>();
        self.remove_many(expired_tokens)
    }

    pub fn cleanup_expired(&self) -> usize {
        self.purge_expired_tokens()
    }

    pub fn backend(&self) -> Backend {
        self.0.backend.clone()
    }

    fn tokens_for_user(
        &self,
        user_id: UserIdInDb,
    ) -> dashmap::mapref::one::RefMut<'_, UserIdInDb, DashMap<String, ()>> {
        self.0.user_tokens.entry(user_id).or_default()
    }

    fn is_expired(expires_at: Instant) -> bool {
        Instant::now() >= expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcState {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: Option<String>,
    pub pkce_used: bool,
    pub consumed: bool,
    pub expires_at: Instant,
}

#[derive(Debug)]
struct OidcStateStoreInner {
    states: DashMap<String, OidcState>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct OidcStateStore(Arc<OidcStateStoreInner>);

impl OidcStateStore {
    pub fn new() -> Self {
        Self::with_ttl_and_cleanup_interval(OIDC_STATE_TTL, CLEANUP_INTERVAL)
    }

    pub(crate) fn with_ttl_and_cleanup_interval(ttl: Duration, cleanup_interval: Duration) -> Self {
        let store = Self(Arc::new(OidcStateStoreInner {
            states: DashMap::new(),
            ttl,
        }));
        store.spawn_cleanup_loop(cleanup_interval);
        store
    }

    fn spawn_cleanup_loop(&self, cleanup_interval: Duration) {
        let inner = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(cleanup_interval).await;
                let Some(inner) = inner.upgrade() else {
                    break;
                };
                let store = OidcStateStore(inner);
                store.cleanup_expired();
            }
        });
    }

    pub fn insert(
        &self,
        state: impl Into<String>,
        nonce: impl Into<String>,
        pkce_verifier: Option<String>,
        pkce_used: bool,
    ) -> OidcState {
        let state = state.into();
        let entry = OidcState {
            state: state.clone(),
            nonce: nonce.into(),
            pkce_verifier,
            pkce_used,
            consumed: false,
            expires_at: Instant::now() + self.0.ttl,
        };
        self.0.states.insert(state, entry.clone());
        entry
    }

    pub fn get(&self, state: &str) -> Option<OidcState> {
        let entry = self.0.states.get(state).map(|entry| entry.clone())?;
        if Self::is_expired(entry.expires_at) {
            self.remove(state);
            return None;
        }
        Some(entry)
    }

    pub fn consume(&self, state: &str) -> Option<OidcState> {
        let mut entry = self.0.states.get_mut(state)?;
        if Self::is_expired(entry.expires_at) {
            drop(entry);
            self.remove(state);
            return None;
        }
        if entry.consumed {
            return None;
        }
        entry.consumed = true;
        Some(entry.clone())
    }

    pub fn remove(&self, state: &str) -> Option<OidcState> {
        self.0.states.remove(state).map(|(_, entry)| entry)
    }

    pub fn remove_many<I, K>(&self, states: I) -> usize
    where
        I: IntoIterator<Item = K>,
        K: AsRef<str>,
    {
        states
            .into_iter()
            .filter(|state| self.remove(state.as_ref()).is_some())
            .count()
    }

    pub fn cleanup_expired(&self) -> usize {
        let expired_states = self
            .0
            .states
            .iter()
            .filter_map(|entry| Self::is_expired(entry.expires_at).then(|| entry.key().clone()))
            .collect::<Vec<_>>();
        self.remove_many(expired_states)
    }

    fn is_expired(expires_at: Instant) -> bool {
        Instant::now() >= expires_at
    }
}

impl Default for OidcStateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptchaChallenge {
    pub challenge_id: String,
    pub answer: String,
    pub expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptchaChallengeVerifyFailure {
    Missing,
    Expired,
    Incorrect,
    Consumed,
}

#[derive(Debug)]
struct CaptchaChallengeStoreInner {
    challenges: DashMap<String, CaptchaChallenge>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct CaptchaChallengeStore(Arc<CaptchaChallengeStoreInner>);

impl CaptchaChallengeStore {
    pub fn new() -> Self {
        Self::with_ttl_and_cleanup_interval(CAPTCHA_CHALLENGE_TTL, CLEANUP_INTERVAL)
    }

    pub(crate) fn with_ttl_and_cleanup_interval(ttl: Duration, cleanup_interval: Duration) -> Self {
        let store = Self(Arc::new(CaptchaChallengeStoreInner {
            challenges: DashMap::new(),
            ttl,
        }));
        store.spawn_cleanup_loop(cleanup_interval);
        store
    }

    fn spawn_cleanup_loop(&self, cleanup_interval: Duration) {
        let inner = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(cleanup_interval).await;
                let Some(inner) = inner.upgrade() else {
                    break;
                };
                let store = CaptchaChallengeStore(inner);
                store.cleanup_expired();
            }
        });
    }

    pub fn insert(
        &self,
        challenge_id: impl Into<String>,
        answer: impl Into<String>,
    ) -> CaptchaChallenge {
        let challenge_id = challenge_id.into();
        let entry = CaptchaChallenge {
            challenge_id: challenge_id.clone(),
            answer: answer.into(),
            expires_at: Instant::now() + self.0.ttl,
        };
        self.0.challenges.insert(challenge_id, entry.clone());
        entry
    }

    pub fn get(&self, challenge_id: &str) -> Option<CaptchaChallenge> {
        let entry = self
            .0
            .challenges
            .get(challenge_id)
            .map(|entry| entry.clone())?;
        if Self::is_expired(entry.expires_at) {
            self.remove(challenge_id);
            return None;
        }
        Some(entry)
    }

    pub fn consume(&self, challenge_id: &str) -> Option<CaptchaChallenge> {
        let entry = self.get(challenge_id)?;
        self.remove(challenge_id)?;
        Some(entry)
    }

    pub fn verify_and_consume(&self, challenge_id: &str, answer: &str) -> bool {
        self.verify_and_consume_detailed(challenge_id, answer)
            .is_ok()
    }

    pub fn verify_and_consume_detailed(
        &self,
        challenge_id: &str,
        answer: &str,
    ) -> Result<CaptchaChallenge, CaptchaChallengeVerifyFailure> {
        let Some(entry) = self
            .0
            .challenges
            .get(challenge_id)
            .map(|entry| entry.clone())
        else {
            return Err(CaptchaChallengeVerifyFailure::Missing);
        };

        if Self::is_expired(entry.expires_at) {
            self.remove(challenge_id);
            return Err(CaptchaChallengeVerifyFailure::Expired);
        }

        if !entry.answer.eq_ignore_ascii_case(answer) {
            self.remove(challenge_id);
            return Err(CaptchaChallengeVerifyFailure::Incorrect);
        }

        self.remove(challenge_id)
            .ok_or(CaptchaChallengeVerifyFailure::Consumed)
            .map(|_| entry)
    }

    pub fn remove(&self, challenge_id: &str) -> Option<CaptchaChallenge> {
        self.0
            .challenges
            .remove(challenge_id)
            .map(|(_, entry)| entry)
    }

    pub fn remove_many<I, K>(&self, challenge_ids: I) -> usize
    where
        I: IntoIterator<Item = K>,
        K: AsRef<str>,
    {
        challenge_ids
            .into_iter()
            .filter(|challenge_id| self.remove(challenge_id.as_ref()).is_some())
            .count()
    }

    pub fn cleanup_expired(&self) -> usize {
        let expired_challenges = self
            .0
            .challenges
            .iter()
            .filter_map(|entry| Self::is_expired(entry.expires_at).then(|| entry.key().clone()))
            .collect::<Vec<_>>();
        self.remove_many(expired_challenges)
    }

    fn is_expired(expires_at: Instant) -> bool {
        Instant::now() >= expires_at
    }
}

impl Default for CaptchaChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_backend() -> Backend {
        Backend::new(crate::db::Db::memory_db().await)
    }

    async fn create_user(backend: &Backend, username: &str) -> UserIdInDb {
        backend
            .db()
            .create_user_and_join_users_group(
                username,
                password_auth::generate_hash("password-for-tests"),
            )
            .await
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn bearer_token_store_revokes_all_tokens_for_user() {
        let backend = make_backend().await;
        let user_id = create_user(&backend, "user-7").await;
        let other_user_id = create_user(&backend, "user-9").await;
        let store = BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        );

        store.insert("token-a", user_id);
        store.insert("token-b", user_id);
        store.insert("token-c", other_user_id);

        assert_eq!(store.revoke_all_tokens_for_user(user_id), 2);
        assert_eq!(
            store.resolve_token_detailed("token-a"),
            Err(ResolveTokenFailure::Revoked)
        );
        assert_eq!(
            store.resolve_token_detailed("token-b"),
            Err(ResolveTokenFailure::Revoked)
        );
        assert!(store.resolve_token("token-c").is_some());
    }

    #[tokio::test]
    async fn token_auth_store_issue_and_resolve() {
        let backend = make_backend().await;
        let user_id = create_user(&backend, "issue-user").await;
        let store = BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        );

        let token = store.issue_token(user_id);
        let context = store.resolve_token(&token).unwrap();

        assert_eq!(context.user_id, user_id);
        assert_eq!(context.token, token);
        assert!(context.expires_at > context.issued_at);
        assert_eq!(
            BASE64_URL_SAFE_NO_PAD
                .decode(token.as_bytes())
                .unwrap()
                .len(),
            32
        );
    }

    #[tokio::test]
    async fn token_auth_store_revoke_and_expire() {
        let backend = make_backend().await;
        let user_id = create_user(&backend, "revoke-user").await;
        let store = BearerTokenStore::with_ttl_and_cleanup_interval(
            backend.clone(),
            Duration::from_millis(20),
            Duration::from_secs(1),
        );

        let revoked_token = store.issue_token(user_id);
        assert!(store.revoke_token(&revoked_token));
        assert_eq!(
            store.resolve_token_detailed(&revoked_token),
            Err(ResolveTokenFailure::Revoked)
        );

        let expired_token = store.issue_token(user_id);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            store.resolve_token_detailed(&expired_token),
            Err(ResolveTokenFailure::Expired)
        );

        assert_eq!(
            store.resolve_token_detailed("missing-token"),
            Err(ResolveTokenFailure::Missing)
        );
    }

    #[tokio::test]
    async fn token_auth_store_restart_invalidation() {
        let backend = make_backend().await;
        let user_id = create_user(&backend, "restart-user").await;
        let first_store = BearerTokenStore::with_ttl_and_cleanup_interval(
            backend.clone(),
            Duration::from_secs(60),
            Duration::from_millis(10),
        );

        let token = first_store.issue_token(user_id);
        assert!(first_store.resolve_token(&token).is_some());
        drop(first_store);

        let restarted_store = BearerTokenStore::with_ttl_and_cleanup_interval(
            backend,
            Duration::from_secs(60),
            Duration::from_millis(10),
        );

        assert_eq!(
            restarted_store.resolve_token_detailed(&token),
            Err(ResolveTokenFailure::Missing)
        );
    }

    #[tokio::test]
    async fn oidc_state_store_marks_state_as_consumed_once() {
        let store = OidcStateStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        );

        store.insert("state-1", "nonce-1", Some("verifier".to_string()), true);

        let consumed = store.consume("state-1").unwrap();
        assert!(consumed.consumed);
        assert_eq!(consumed.nonce, "nonce-1");
        assert_eq!(consumed.pkce_verifier.as_deref(), Some("verifier"));
        assert!(store.consume("state-1").is_none());
        assert!(store.get("state-1").unwrap().consumed);
    }

    #[tokio::test]
    async fn oidc_state_store_restart_invalidation() {
        let first_store = OidcStateStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        );

        first_store.insert(
            "oidc-restart-state",
            "nonce",
            Some("verifier".to_string()),
            true,
        );
        assert!(first_store.get("oidc-restart-state").is_some());
        drop(first_store);

        let restarted_store = OidcStateStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        );

        assert!(restarted_store.get("oidc-restart-state").is_none());
        assert!(restarted_store.consume("oidc-restart-state").is_none());
    }

    #[tokio::test]
    async fn captcha_store_verifies_then_removes_challenge() {
        let store = CaptchaChallengeStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        );

        store.insert("captcha-1", "AbCd");

        assert!(!store.verify_and_consume("captcha-1", "nope"));
        assert!(store.get("captcha-1").is_some());
        assert!(store.verify_and_consume("captcha-1", "aBcD"));
        assert!(store.get("captcha-1").is_none());
    }

    #[tokio::test]
    async fn captcha_header_restart_invalidates_old_challenge() {
        let first_store = CaptchaChallengeStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        );

        first_store.insert("captcha-restart", "AbCd");
        assert!(first_store.verify_and_consume("captcha-restart", "AbCd"));

        let first_store = CaptchaChallengeStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        );
        first_store.insert("captcha-restart-2", "EfGh");
        assert!(first_store.get("captcha-restart-2").is_some());
        drop(first_store);

        let restarted_store = CaptchaChallengeStore::with_ttl_and_cleanup_interval(
            Duration::from_secs(60),
            Duration::from_millis(10),
        );

        assert_eq!(
            restarted_store.verify_and_consume_detailed("captcha-restart-2", "EfGh"),
            Err(CaptchaChallengeVerifyFailure::Missing)
        );
    }

    #[tokio::test]
    async fn cleanup_loop_evicts_expired_entries() {
        let bearer_store = BearerTokenStore::with_ttl_and_cleanup_interval(
            make_backend().await,
            Duration::from_millis(20),
            Duration::from_millis(10),
        );
        let oidc_store = OidcStateStore::with_ttl_and_cleanup_interval(
            Duration::from_millis(20),
            Duration::from_millis(10),
        );
        let captcha_store = CaptchaChallengeStore::with_ttl_and_cleanup_interval(
            Duration::from_millis(20),
            Duration::from_millis(10),
        );

        bearer_store.insert("token-expired", 1);
        oidc_store.insert("state-expired", "nonce", None, false);
        captcha_store.insert("captcha-expired", "1234");

        tokio::time::sleep(Duration::from_millis(60)).await;

        assert!(bearer_store.get("token-expired").is_none());
        assert!(oidc_store.get("state-expired").is_none());
        assert!(captcha_store.get("captcha-expired").is_none());
    }
}
