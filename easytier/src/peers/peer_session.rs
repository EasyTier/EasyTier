use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};

use anyhow::anyhow;
use dashmap::DashMap;

use super::secure_datagram::{SecureDatagramDirection, SecureDatagramSession};
use crate::{
    common::PeerId,
    tunnel::packet_def::ZCPacket,
};

pub struct UpsertResponderSessionReturn {
    pub session: Arc<PeerSession>,
    pub action: PeerSessionAction,
    pub session_generation: u32,
    pub root_key: Option<[u8; 32]>,
    pub initial_epoch: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerSessionAction {
    Join,
    Sync,
    Create,
}

#[derive(PartialEq, Clone, Eq, Hash, Debug)]
pub struct SessionKey {
    network_name: String,
    peer_id: PeerId,
}

impl SessionKey {
    pub fn new(network_name: String, peer_id: PeerId) -> Self {
        Self {
            network_name,
            peer_id,
        }
    }
}

#[derive(Clone)]
pub struct PeerSessionStore {
    sessions: Arc<DashMap<SessionKey, Arc<PeerSession>>>,
}

impl Default for PeerSessionStore {
    fn default() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }
}

impl PeerSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &SessionKey) -> Option<Arc<PeerSession>> {
        let session = self.sessions.get(key)?.clone();
        if session.is_valid() {
            Some(session)
        } else {
            self.sessions.remove(key);
            None
        }
    }

    pub fn remove(&self, key: &SessionKey) {
        self.sessions.remove(key);
    }

    pub fn insert_session(&self, key: SessionKey, session: Arc<PeerSession>) {
        self.sessions.insert(key, session);
    }

    pub fn evict_unused_sessions(&self) {
        self.sessions
            .retain(|_key, session| Arc::strong_count(session) > 1);
    }

    #[tracing::instrument(skip(self))]
    pub fn upsert_responder_session(
        &self,
        key: &SessionKey,
        a_session_generation: Option<u32>,
        send_algorithm: String,
        recv_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<UpsertResponderSessionReturn, anyhow::Error> {
        tracing::event!(tracing::Level::INFO, "upsert_responder_session {:?}", key);
        let existing = self
            .sessions
            .get(key)
            .map(|v| v.clone())
            .filter(|s| s.is_valid());
        match existing {
            None => {
                let root_key = PeerSession::new_root_key();
                let session_generation = 1u32;
                let initial_epoch = 0u32;
                let session = Arc::new(PeerSession::new(
                    key.peer_id,
                    root_key,
                    session_generation,
                    initial_epoch,
                    send_algorithm,
                    recv_algorithm,
                    peer_static_pubkey,
                ));
                self.sessions.insert(key.clone(), session.clone());
                Ok(UpsertResponderSessionReturn {
                    session,
                    action: PeerSessionAction::Create,
                    session_generation,
                    root_key: Some(root_key),
                    initial_epoch,
                })
            }
            Some(session) => {
                session.check_encrypt_algo_same(&send_algorithm, &recv_algorithm)?;
                session.check_or_set_peer_static_pubkey(peer_static_pubkey)?;
                let local_gen = session.session_generation();
                if a_session_generation.is_some_and(|g| g == local_gen) {
                    Ok(UpsertResponderSessionReturn {
                        session,
                        action: PeerSessionAction::Join,
                        session_generation: local_gen,
                        root_key: None,
                        initial_epoch: 0,
                    })
                } else {
                    let initial_epoch = session.next_sync_epoch();
                    let root_key = session.root_key();
                    Ok(UpsertResponderSessionReturn {
                        session,
                        action: PeerSessionAction::Sync,
                        session_generation: local_gen,
                        root_key: Some(root_key),
                        initial_epoch,
                    })
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip(self))]
    pub fn apply_initiator_action(
        &self,
        key: &SessionKey,
        action: PeerSessionAction,
        b_session_generation: u32,
        root_key_32: Option<[u8; 32]>,
        initial_epoch: u32,
        send_algorithm: String,
        recv_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<Arc<PeerSession>, anyhow::Error> {
        tracing::event!(tracing::Level::INFO, "apply_initiator_action {:?}", key);
        match action {
            PeerSessionAction::Join => {
                let Some(session) = self.get(key) else {
                    return Err(anyhow!("no local session for JOIN"));
                };
                session.check_encrypt_algo_same(&send_algorithm, &recv_algorithm)?;
                session.check_or_set_peer_static_pubkey(peer_static_pubkey)?;
                if session.session_generation() != b_session_generation {
                    return Err(anyhow!("JOIN generation mismatch"));
                }
                Ok(session)
            }
            PeerSessionAction::Sync | PeerSessionAction::Create => {
                let root_key = root_key_32.ok_or_else(|| anyhow!("missing root_key"))?;
                if let Some(existing) = self.sessions.get(key)
                    && !existing.is_valid()
                {
                    drop(existing);
                    self.sessions.remove(key);
                }
                let session = self
                    .sessions
                    .entry(key.clone())
                    .or_insert_with(|| {
                        Arc::new(PeerSession::new(
                            key.peer_id,
                            root_key,
                            b_session_generation,
                            initial_epoch,
                            send_algorithm.clone(),
                            recv_algorithm.clone(),
                            peer_static_pubkey,
                        ))
                    })
                    .clone();
                session.check_encrypt_algo_same(&send_algorithm, &recv_algorithm)?;
                session.check_or_set_peer_static_pubkey(peer_static_pubkey)?;
                session.sync_root_key(
                    root_key,
                    b_session_generation,
                    initial_epoch,
                    matches!(action, PeerSessionAction::Sync),
                );
                Ok(session)
            }
        }
    }
}

pub struct PeerSession {
    peer_id: PeerId,
    peer_static_pubkey: RwLock<Option<[u8; 32]>>,
    datagram: SecureDatagramSession,
    invalidated: AtomicBool,
}

impl std::fmt::Debug for PeerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerSession")
            .field("peer_id", &self.peer_id)
            .field("peer_static_pubkey", &self.peer_static_pubkey)
            .field("datagram", &self.datagram)
            .finish()
    }
}

impl PeerSession {
    const SYNC_RX_GRACE_AFTER_MS: u64 = SecureDatagramSession::SYNC_RX_GRACE_AFTER_MS;

    pub fn new(
        peer_id: PeerId,
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        send_cipher_algorithm: String,
        recv_cipher_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Self {
        Self {
            peer_id,
            peer_static_pubkey: RwLock::new(peer_static_pubkey),
            datagram: SecureDatagramSession::new(
                root_key,
                session_generation,
                initial_epoch,
                send_cipher_algorithm,
                recv_cipher_algorithm,
            ),
            invalidated: AtomicBool::new(false),
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn invalidate(&self) {
        self.invalidated.store(true, Ordering::Relaxed);
        self.datagram.invalidate();
    }

    pub fn is_valid(&self) -> bool {
        !self.invalidated.load(Ordering::Relaxed) && self.datagram.is_valid()
    }

    pub fn session_generation(&self) -> u32 {
        self.datagram.session_generation()
    }

    pub fn root_key(&self) -> [u8; 32] {
        self.datagram.root_key()
    }

    pub fn new_root_key() -> [u8; 32] {
        SecureDatagramSession::new_root_key()
    }

    pub fn next_sync_epoch(&self) -> u32 {
        self.datagram.next_sync_epoch()
    }

    pub fn check_encrypt_algo_same(
        &self,
        send_algorithm: &str,
        recv_algorithm: &str,
    ) -> Result<(), anyhow::Error> {
        self.datagram
            .check_encrypt_algo_same(send_algorithm, recv_algorithm)
    }

    pub fn check_or_set_peer_static_pubkey(
        &self,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<(), anyhow::Error> {
        let Some(peer_static_pubkey) = peer_static_pubkey else {
            return Ok(());
        };
        let mut guard = self.peer_static_pubkey.write().unwrap();
        if let Some(existing) = *guard {
            if existing != peer_static_pubkey {
                return Err(anyhow!("peer static pubkey mismatch"));
            }
            return Ok(());
        }
        *guard = Some(peer_static_pubkey);
        Ok(())
    }

    pub fn sync_root_key(
        &self,
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        preserve_rx_grace: bool,
    ) {
        self.datagram.sync_root_key(
            root_key,
            session_generation,
            initial_epoch,
            preserve_rx_grace,
        );
    }

    pub fn dir_for_sender(
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
    ) -> SecureDatagramDirection {
        if sender_peer_id < receiver_peer_id {
            SecureDatagramDirection::AToB
        } else {
            SecureDatagramDirection::BToA
        }
    }

    pub fn encrypt_payload(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        pkt: &mut ZCPacket,
    ) -> Result<(), anyhow::Error> {
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        self.datagram
            .encrypt_payload(Self::dir_for_sender(sender_peer_id, receiver_peer_id), pkt)
    }

    pub fn decrypt_payload(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        ciphertext_with_tail: &mut ZCPacket,
    ) -> Result<(), anyhow::Error> {
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        self.datagram.decrypt_payload(
            Self::dir_for_sender(sender_peer_id, receiver_peer_id),
            ciphertext_with_tail,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_session_supports_asymmetric_algorithms() {
        let a: PeerId = 10;
        let b: PeerId = 20;
        let root_key = PeerSession::new_root_key();
        let generation = 1u32;
        let initial_epoch = 0u32;

        let sa = PeerSession::new(
            b,
            root_key,
            generation,
            initial_epoch,
            "aes-256-gcm".to_string(),
            "chacha20-poly1305".to_string(),
            None,
        );
        let sb = PeerSession::new(
            a,
            root_key,
            generation,
            initial_epoch,
            "chacha20-poly1305".to_string(),
            "aes-256-gcm".to_string(),
            None,
        );

        let plaintext1 = b"hello from a";
        let mut pkt1 = ZCPacket::new_with_payload(plaintext1);
        pkt1.fill_peer_manager_hdr(a as u32, b as u32, 0);
        sa.encrypt_payload(a, b, &mut pkt1).unwrap();
        sb.decrypt_payload(a, b, &mut pkt1).unwrap();
        assert_eq!(pkt1.payload(), plaintext1);

        let plaintext2 = b"hello from b";
        let mut pkt2 = ZCPacket::new_with_payload(plaintext2);
        pkt2.fill_peer_manager_hdr(b as u32, a as u32, 0);
        sb.encrypt_payload(b, a, &mut pkt2).unwrap();
        sa.decrypt_payload(b, a, &mut pkt2).unwrap();
        assert_eq!(pkt2.payload(), plaintext2);
    }

    #[test]
    fn sync_root_key_preserves_generic_grace_window_constant() {
        assert_eq!(
            PeerSession::SYNC_RX_GRACE_AFTER_MS,
            SecureDatagramSession::SYNC_RX_GRACE_AFTER_MS
        );
    }
}
