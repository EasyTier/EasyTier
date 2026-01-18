use std::{
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;
use dashmap::DashMap;
use hmac::{Hmac, Mac as _};
use rand::RngCore as _;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::Sha256;
use zerocopy::AsBytes;

use super::PeerId;

type HmacSha256 = Hmac<Sha256>;

#[repr(C, packed)]
#[derive(AsBytes, Clone, Copy, Debug, Default)]
pub struct SessionAeadTail {
    pub tag: [u8; 16],
    pub nonce: [u8; 12],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerSessionAction {
    Join,
    Sync,
    Create,
}

#[derive(Clone)]
pub struct PeerSessionStore {
    sessions: Arc<DashMap<PeerId, Arc<PeerSession>>>,
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

    pub fn get(&self, peer_id: PeerId) -> Option<Arc<PeerSession>> {
        self.sessions.get(&peer_id).map(|v| v.clone())
    }

    pub fn upsert_responder_session(
        &self,
        peer_id: PeerId,
        a_session_generation: Option<u32>,
        algorithm: String,
    ) -> (
        Arc<PeerSession>,
        PeerSessionAction,
        u32,
        Option<[u8; 32]>,
        u32,
    ) {
        let existing = self.sessions.get(&peer_id).map(|v| v.clone());
        match existing {
            None => {
                let root_key = PeerSession::new_root_key();
                let session_generation = 1u32;
                let initial_epoch = 0u32;
                let session = Arc::new(PeerSession::new(
                    peer_id,
                    root_key,
                    session_generation,
                    initial_epoch,
                    algorithm,
                ));
                self.sessions.insert(peer_id, session.clone());
                (
                    session,
                    PeerSessionAction::Create,
                    session_generation,
                    Some(root_key),
                    initial_epoch,
                )
            }
            Some(session) => {
                let local_gen = session.session_generation();
                if a_session_generation.is_some_and(|g| g == local_gen) {
                    (session, PeerSessionAction::Join, local_gen, None, 0)
                } else {
                    let initial_epoch = session.next_sync_epoch();
                    let root_key = session.root_key();
                    (
                        session,
                        PeerSessionAction::Sync,
                        local_gen,
                        Some(root_key),
                        initial_epoch,
                    )
                }
            }
        }
    }

    pub fn apply_initiator_action(
        &self,
        peer_id: PeerId,
        action: PeerSessionAction,
        b_session_generation: u32,
        root_key_32: Option<[u8; 32]>,
        initial_epoch: u32,
        algorithm: String,
    ) -> Result<Arc<PeerSession>, anyhow::Error> {
        println!("apply_initiator_action {:?}", action);
        match action {
            PeerSessionAction::Join => {
                let Some(session) = self.get(peer_id) else {
                    return Err(anyhow!("no local session for JOIN"));
                };
                if session.session_generation() != b_session_generation {
                    return Err(anyhow!("JOIN generation mismatch"));
                }
                Ok(session)
            }
            PeerSessionAction::Sync | PeerSessionAction::Create => {
                let root_key = root_key_32.ok_or_else(|| anyhow!("missing root_key"))?;
                let session = self
                    .sessions
                    .entry(peer_id)
                    .or_insert_with(|| {
                        Arc::new(PeerSession::new(
                            peer_id,
                            root_key,
                            b_session_generation,
                            initial_epoch,
                            algorithm.clone(),
                        ))
                    })
                    .clone();
                session.sync_root_key(root_key, b_session_generation, initial_epoch);
                Ok(session)
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
struct EpochKeySlot {
    epoch: u32,
    generation: u32,
    key: [u8; 32],
    valid: bool,
}

#[derive(Clone, Copy, Default)]
struct ReplayWindow256 {
    max_seq: u64,
    bitmap: [u8; 32],
    valid: bool,
}

impl ReplayWindow256 {
    fn clear(&mut self) {
        self.max_seq = 0;
        self.bitmap.fill(0);
        self.valid = false;
    }

    fn test_bit(&self, idx: usize) -> bool {
        let byte = idx / 8;
        let bit = idx % 8;
        (self.bitmap[byte] >> bit) & 1 == 1
    }

    fn set_bit(&mut self, idx: usize) {
        let byte = idx / 8;
        let bit = idx % 8;
        self.bitmap[byte] |= 1u8 << bit;
    }

    fn shift_right(&mut self, shift: usize) {
        if shift == 0 {
            return;
        }
        let total_bits = 256usize;
        if shift >= total_bits {
            self.bitmap.fill(0);
            return;
        }

        let byte_shift = shift / 8;
        let bit_shift = shift % 8;

        if byte_shift > 0 {
            for i in (0..self.bitmap.len()).rev() {
                self.bitmap[i] = if i >= byte_shift {
                    self.bitmap[i - byte_shift]
                } else {
                    0
                };
            }
        }

        if bit_shift > 0 {
            let mut carry = 0u8;
            for b in self.bitmap.iter_mut().rev() {
                let new_carry = *b << (8 - bit_shift);
                *b = (*b >> bit_shift) | carry;
                carry = new_carry;
            }
        }
    }

    fn accept(&mut self, seq: u64) -> bool {
        if !self.valid {
            self.valid = true;
            self.max_seq = seq;
            self.set_bit(0);
            return true;
        }

        if seq > self.max_seq {
            let shift = (seq - self.max_seq) as usize;
            self.shift_right(shift);
            self.max_seq = seq;
            self.set_bit(0);
            return true;
        }

        let delta = (self.max_seq - seq) as usize;
        if delta >= 256 {
            return false;
        }
        if self.test_bit(delta) {
            return false;
        }
        self.set_bit(delta);
        true
    }
}

#[derive(Clone, Copy, Default)]
struct EpochRxSlot {
    epoch: u32,
    window: ReplayWindow256,
    last_rx_ms: u64,
    valid: bool,
}

impl EpochRxSlot {
    fn clear(&mut self) {
        self.epoch = 0;
        self.window.clear();
        self.last_rx_ms = 0;
        self.valid = false;
    }
}

pub struct PeerSession {
    peer_id: PeerId,
    algorithm: String,
    root_key: RwLock<[u8; 32]>,
    session_generation: AtomicU32,

    send_epoch: AtomicU32,
    send_seq: [AtomicU64; 2],
    send_epoch_started_ms: AtomicU64,
    send_packets_since_epoch: AtomicU64,

    rx_slots: Mutex<[[EpochRxSlot; 2]; 2]>,
    key_cache: Mutex<[[EpochKeySlot; 2]; 2]>,
}

impl PeerSession {
    const EVICT_IDLE_AFTER_MS: u64 = 30_000;
    const ROTATE_AFTER_PACKETS: u64 = 1_000_000;
    const ROTATE_AFTER_MS: u64 = 10 * 60 * 1000;

    pub fn new(
        peer_id: PeerId,
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        algorithm: String,
    ) -> Self {
        let rx_slots = [
            [EpochRxSlot::default(), EpochRxSlot::default()],
            [EpochRxSlot::default(), EpochRxSlot::default()],
        ];
        let key_cache = [
            [EpochKeySlot::default(), EpochKeySlot::default()],
            [EpochKeySlot::default(), EpochKeySlot::default()],
        ];
        let now_ms = now_ms();
        Self {
            peer_id,
            algorithm,
            root_key: RwLock::new(root_key),
            session_generation: AtomicU32::new(session_generation),
            send_epoch: AtomicU32::new(initial_epoch),
            send_seq: [AtomicU64::new(0), AtomicU64::new(0)],
            send_epoch_started_ms: AtomicU64::new(now_ms),
            send_packets_since_epoch: AtomicU64::new(0),
            rx_slots: Mutex::new(rx_slots),
            key_cache: Mutex::new(key_cache),
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn session_generation(&self) -> u32 {
        self.session_generation.load(Ordering::Relaxed)
    }

    pub fn root_key(&self) -> [u8; 32] {
        *self.root_key.read().unwrap()
    }

    pub fn new_root_key() -> [u8; 32] {
        let mut out = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut out);
        out
    }

    pub fn next_sync_epoch(&self) -> u32 {
        let send_epoch = self.send_epoch.load(Ordering::Relaxed);
        let rx = self.rx_slots.lock().unwrap();
        let mut max_epoch = send_epoch;
        for dir in 0..2 {
            let cur = rx[dir][0];
            if cur.valid {
                max_epoch = max_epoch.max(cur.epoch);
            }
            let prev = rx[dir][1];
            if prev.valid {
                max_epoch = max_epoch.max(prev.epoch);
            }
        }
        max_epoch.wrapping_add(1)
    }

    pub fn sync_root_key(&self, root_key: [u8; 32], session_generation: u32, initial_epoch: u32) {
        {
            let mut g = self.root_key.write().unwrap();
            *g = root_key;
        }
        self.session_generation
            .store(session_generation, Ordering::Relaxed);

        self.send_epoch.store(initial_epoch, Ordering::Relaxed);
        self.send_seq[0].store(0, Ordering::Relaxed);
        self.send_seq[1].store(0, Ordering::Relaxed);
        self.send_epoch_started_ms
            .store(now_ms(), Ordering::Relaxed);
        self.send_packets_since_epoch.store(0, Ordering::Relaxed);

        {
            let mut rx = self.rx_slots.lock().unwrap();
            for dir in 0..2 {
                rx[dir][0] = EpochRxSlot {
                    epoch: initial_epoch,
                    window: ReplayWindow256::default(),
                    last_rx_ms: 0,
                    valid: true,
                };
                rx[dir][1].clear();
            }
        }

        self.key_cache
            .lock()
            .unwrap()
            .fill([EpochKeySlot::default(), EpochKeySlot::default()]);
    }

    pub fn dir_for_sender(sender_peer_id: PeerId, receiver_peer_id: PeerId) -> usize {
        if sender_peer_id < receiver_peer_id {
            0
        } else {
            1
        }
    }

    fn hkdf_traffic_key(&self, epoch: u32, dir: usize) -> [u8; 32] {
        let root_key = self.root_key();
        let salt = [0u8; 32];
        let mut extract = HmacSha256::new_from_slice(&salt).unwrap();
        extract.update(&root_key);
        let prk = extract.finalize().into_bytes();

        let mut info = Vec::with_capacity(9 + 4 + 1);
        info.extend_from_slice(b"et-traffic");
        info.extend_from_slice(&epoch.to_be_bytes());
        info.push(dir as u8);

        let mut expand = HmacSha256::new_from_slice(&prk).unwrap();
        expand.update(&info);
        expand.update(&[1u8]);
        let okm = expand.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[..32]);
        key
    }

    fn get_key(&self, epoch: u32, dir: usize) -> Option<[u8; 32]> {
        let generation = self.session_generation();
        let rx = self.rx_slots.lock().unwrap();
        let send_epoch = self.send_epoch.load(Ordering::Relaxed);
        let allowed = epoch == send_epoch
            || rx[dir][0].valid && rx[dir][0].epoch == epoch
            || rx[dir][1].valid && rx[dir][1].epoch == epoch;
        if !allowed {
            return None;
        }

        let mut guard = self.key_cache.lock().unwrap();
        for slot in guard[dir].iter_mut() {
            if slot.valid && slot.epoch == epoch && slot.generation == generation {
                return Some(slot.key);
            }
        }

        let key = self.hkdf_traffic_key(epoch, dir);
        if !guard[dir][0].valid || guard[dir][0].epoch == epoch {
            guard[dir][0] = EpochKeySlot {
                epoch,
                generation,
                key,
                valid: true,
            };
        } else {
            guard[dir][1] = EpochKeySlot {
                epoch,
                generation,
                key,
                valid: true,
            };
        }
        Some(key)
    }

    fn maybe_rotate_epoch(&self, now_ms: u64) {
        let packets = self
            .send_packets_since_epoch
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        let started = self.send_epoch_started_ms.load(Ordering::Relaxed);
        if packets < Self::ROTATE_AFTER_PACKETS
            && now_ms.saturating_sub(started) < Self::ROTATE_AFTER_MS
        {
            return;
        }

        let cur = self.send_epoch.load(Ordering::Relaxed);
        let next = cur.wrapping_add(1);
        if self
            .send_epoch
            .compare_exchange(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.send_epoch_started_ms.store(now_ms, Ordering::Relaxed);
            self.send_packets_since_epoch.store(0, Ordering::Relaxed);
        }
    }

    fn next_nonce(&self, dir: usize) -> (u32, u64, [u8; 12]) {
        let now_ms = now_ms();
        self.maybe_rotate_epoch(now_ms);
        let epoch = self.send_epoch.load(Ordering::Relaxed);
        let seq = self.send_seq[dir].fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&epoch.to_be_bytes());
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        (epoch, seq, nonce)
    }

    fn parse_tail(payload: &[u8]) -> Option<(usize, [u8; 12])> {
        if payload.len() < std::mem::size_of::<SessionAeadTail>() {
            return None;
        }
        let tail_off = payload.len() - std::mem::size_of::<SessionAeadTail>();
        let tail = &payload[tail_off..];
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&tail[16..]);
        Some((tail_off, nonce))
    }

    fn select_alg(&self) -> &'static aead::Algorithm {
        match self.algorithm.as_str() {
            "aes-gcm" | "aes-256-gcm" | "aes-256-gcm-session" => &aead::AES_256_GCM,
            "chacha20" | "chacha20-session" | "chacha20-poly1305" => &aead::CHACHA20_POLY1305,
            _ => &aead::AES_256_GCM,
        }
    }

    fn evict_old_rx_slots(rx: &mut [[EpochRxSlot; 2]; 2], now_ms: u64) {
        for dir_slots in rx.iter_mut() {
            for slot in dir_slots.iter_mut() {
                if !slot.valid {
                    continue;
                }
                let last = slot.last_rx_ms;
                if last != 0 && now_ms.saturating_sub(last) > Self::EVICT_IDLE_AFTER_MS {
                    slot.clear();
                }
            }
        }
    }

    fn check_replay(&self, epoch: u32, seq: u64, dir: usize, now_ms: u64) -> bool {
        let mut rx = self.rx_slots.lock().unwrap();
        Self::evict_old_rx_slots(&mut rx, now_ms);
        let send_epoch = self.send_epoch.load(Ordering::Relaxed);
        {
            let mut key_cache = self.key_cache.lock().unwrap();
            for d in 0..2 {
                for s in 0..2 {
                    if !key_cache[d][s].valid {
                        continue;
                    }
                    let e = key_cache[d][s].epoch;
                    let allowed = e == send_epoch
                        || rx[d][0].valid && rx[d][0].epoch == e
                        || rx[d][1].valid && rx[d][1].epoch == e;
                    if !allowed {
                        key_cache[d][s].valid = false;
                    }
                }
            }
        }

        if !rx[dir][0].valid {
            rx[dir][0] = EpochRxSlot {
                epoch,
                window: ReplayWindow256::default(),
                last_rx_ms: now_ms,
                valid: true,
            };
        }

        if rx[dir][0].valid && epoch == rx[dir][0].epoch {
            rx[dir][0].last_rx_ms = now_ms;
            return rx[dir][0].window.accept(seq);
        }

        if rx[dir][1].valid && epoch == rx[dir][1].epoch {
            rx[dir][1].last_rx_ms = now_ms;
            return rx[dir][1].window.accept(seq);
        }

        if rx[dir][0].valid && epoch > rx[dir][0].epoch {
            rx[dir][1] = rx[dir][0];
            rx[dir][0] = EpochRxSlot {
                epoch,
                window: ReplayWindow256::default(),
                last_rx_ms: now_ms,
                valid: true,
            };
            return rx[dir][0].window.accept(seq);
        }

        false
    }

    pub fn encrypt_payload(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, SessionAeadTail), anyhow::Error> {
        let dir = Self::dir_for_sender(sender_peer_id, receiver_peer_id);
        let (epoch, _seq, nonce_bytes) = self.next_nonce(dir);
        let key = self
            .get_key(epoch, dir)
            .ok_or_else(|| anyhow!("no key for epoch"))?;

        let alg = self.select_alg();
        let cipher =
            LessSafeKey::new(UnboundKey::new(alg, &key).map_err(|_| anyhow!("invalid key"))?);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut out = plaintext.to_vec();
        let tag = cipher
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut out)
            .map_err(|_| anyhow!("seal failed"))?;

        let mut tail = SessionAeadTail::default();
        tail.tag.copy_from_slice(tag.as_ref());
        tail.nonce.copy_from_slice(&nonce_bytes);
        Ok((out, tail))
    }

    pub fn decrypt_payload(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        ciphertext_with_tail: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        let dir = Self::dir_for_sender(sender_peer_id, receiver_peer_id);
        let (cipher_len, nonce_bytes) =
            Self::parse_tail(ciphertext_with_tail).ok_or_else(|| anyhow!("no tail"))?;
        let epoch = u32::from_be_bytes(nonce_bytes[..4].try_into().unwrap());
        let seq = u64::from_be_bytes(nonce_bytes[4..].try_into().unwrap());

        let now_ms = now_ms();
        if !self.check_replay(epoch, seq, dir, now_ms) {
            return Err(anyhow!("replay rejected"));
        }

        let key = self
            .get_key(epoch, dir)
            .ok_or_else(|| anyhow!("no key for epoch"))?;

        let alg = self.select_alg();
        let cipher =
            LessSafeKey::new(UnboundKey::new(alg, &key).map_err(|_| anyhow!("invalid key"))?);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let text_and_tag_len = cipher_len + 16;
        if ciphertext_with_tail.len() < text_and_tag_len + 12 {
            return Err(anyhow!("invalid payload length"));
        }
        let mut buf = ciphertext_with_tail[..text_and_tag_len].to_vec();
        let plain = cipher
            .open_in_place(nonce, Aad::empty(), &mut buf)
            .map_err(|_| anyhow!("open failed"))?;
        Ok(plain.to_vec())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
