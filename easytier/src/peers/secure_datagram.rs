use std::{
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;
use atomic_shim::AtomicU64;
use hmac::{Hmac, Mac as _};
use rand::RngCore as _;
use sha2::Sha256;
use zerocopy::FromBytes;

use crate::{
    peers::encrypt::{Encryptor, create_encryptor},
    tunnel::packet_def::{StandardAeadTail, ZCPacket},
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureDatagramDirection {
    AToB,
    BToA,
}

impl SecureDatagramDirection {
    fn idx(self) -> usize {
        match self {
            Self::AToB => 0,
            Self::BToA => 1,
        }
    }
}

#[derive(Clone, Default)]
struct EpochKeySlot {
    epoch: u32,
    generation: u32,
    valid: bool,
    send_cipher: Option<Arc<dyn Encryptor>>,
    recv_cipher: Option<Arc<dyn Encryptor>>,
}

impl std::fmt::Debug for EpochKeySlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochKeySlot")
            .field("epoch", &self.epoch)
            .field("generation", &self.generation)
            .field("valid", &self.valid)
            .finish()
    }
}

impl EpochKeySlot {
    fn get_encryptor(&self, is_send: bool) -> Arc<dyn Encryptor> {
        if is_send {
            self.send_cipher.as_ref().unwrap().clone()
        } else {
            self.recv_cipher.as_ref().unwrap().clone()
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
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
            for b in self.bitmap.iter_mut() {
                let new_carry = *b >> (8 - bit_shift);
                *b = (*b << bit_shift) | carry;
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

    fn can_accept(&self, seq: u64) -> bool {
        if !self.valid || seq > self.max_seq {
            return true;
        }

        let delta = (self.max_seq - seq) as usize;
        delta < 256 && !self.test_bit(delta)
    }
}

#[derive(Debug, Clone, Copy, Default)]
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

#[derive(Debug, Clone, Copy, Default)]
struct SyncRxGrace {
    slots: [[EpochRxSlot; 2]; 2],
    expires_at_ms: u64,
    valid: bool,
}

impl SyncRxGrace {
    fn clear(&mut self) {
        self.slots = [[EpochRxSlot::default(), EpochRxSlot::default()]; 2];
        self.expires_at_ms = 0;
        self.valid = false;
    }

    fn refresh(&mut self, slots: [[EpochRxSlot; 2]; 2], expires_at_ms: u64) {
        self.slots = slots;
        self.expires_at_ms = expires_at_ms;
        self.valid = true;
    }

    fn maybe_expire(&mut self, now_ms: u64) {
        if self.valid && now_ms >= self.expires_at_ms {
            self.clear();
        }
    }
}

pub struct SecureDatagramSession {
    root_key: RwLock<[u8; 32]>,
    session_generation: AtomicU32,

    send_epoch: AtomicU32,
    send_seq: [AtomicU64; 2],
    send_epoch_started_ms: AtomicU64,
    send_packets_since_epoch: AtomicU64,

    rx_slots: Mutex<[[EpochRxSlot; 2]; 2]>,
    key_cache: Mutex<[[EpochKeySlot; 2]; 2]>,
    sync_rx_grace: Mutex<SyncRxGrace>,
    sync_rx_grace_expires_at_ms: AtomicU64,

    send_cipher_algorithm: String,
    recv_cipher_algorithm: String,

    invalidated: AtomicBool,
    decrypt_fail_count: AtomicU32,
}

impl std::fmt::Debug for SecureDatagramSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureDatagramSession")
            .field("root_key", &self.root_key)
            .field("session_generation", &self.session_generation)
            .field("send_epoch", &self.send_epoch)
            .field("send_seq", &self.send_seq)
            .field("send_epoch_started_ms", &self.send_epoch_started_ms)
            .field("send_packets_since_epoch", &self.send_packets_since_epoch)
            .field("rx_slots", &self.rx_slots)
            .field("key_cache", &self.key_cache)
            .field("sync_rx_grace", &self.sync_rx_grace)
            .field(
                "sync_rx_grace_expires_at_ms",
                &self.sync_rx_grace_expires_at_ms,
            )
            .field("send_cipher_algorithm", &self.send_cipher_algorithm)
            .field("recv_cipher_algorithm", &self.recv_cipher_algorithm)
            .finish()
    }
}

impl SecureDatagramSession {
    const EVICT_IDLE_AFTER_MS: u64 = 30_000;
    pub(crate) const SYNC_RX_GRACE_AFTER_MS: u64 = 5_000;
    const ROTATE_AFTER_PACKETS: u64 = 1_000_000;
    const ROTATE_AFTER_MS: u64 = 10 * 60 * 1000;
    const MAX_ACCEPTED_RX_EPOCH_AHEAD: u32 = 3;
    const DECRYPT_FAIL_THRESHOLD: u32 = 10;

    pub fn new(
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        send_cipher_algorithm: String,
        recv_cipher_algorithm: String,
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
            root_key: RwLock::new(root_key),
            session_generation: AtomicU32::new(session_generation),
            send_epoch: AtomicU32::new(initial_epoch),
            send_seq: [AtomicU64::new(0), AtomicU64::new(0)],
            send_epoch_started_ms: AtomicU64::new(now_ms),
            send_packets_since_epoch: AtomicU64::new(0),
            rx_slots: Mutex::new(rx_slots),
            key_cache: Mutex::new(key_cache),
            sync_rx_grace: Mutex::new(SyncRxGrace::default()),
            sync_rx_grace_expires_at_ms: AtomicU64::new(0),
            send_cipher_algorithm,
            recv_cipher_algorithm,
            invalidated: AtomicBool::new(false),
            decrypt_fail_count: AtomicU32::new(0),
        }
    }

    pub fn invalidate(&self) {
        self.invalidated.store(true, Ordering::Relaxed);
    }

    pub fn is_valid(&self) -> bool {
        !self.invalidated.load(Ordering::Relaxed)
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

    pub fn check_encrypt_algo_same(
        &self,
        send_algorithm: &str,
        recv_algorithm: &str,
    ) -> Result<(), anyhow::Error> {
        if self.send_cipher_algorithm != send_algorithm
            || self.recv_cipher_algorithm != recv_algorithm
        {
            return Err(anyhow!("encrypt algorithm not same"));
        }
        Ok(())
    }

    pub fn sync_root_key(
        &self,
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        preserve_rx_grace: bool,
    ) {
        let old_root_key = self.root_key();
        let can_preserve_rx_grace = preserve_rx_grace && old_root_key == root_key;
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
            let mut sync_rx_grace = self.sync_rx_grace.lock().unwrap();
            if can_preserve_rx_grace {
                let expires_at_ms = now_ms().saturating_add(Self::SYNC_RX_GRACE_AFTER_MS);
                sync_rx_grace.refresh(*rx, expires_at_ms);
                self.sync_rx_grace_expires_at_ms
                    .store(expires_at_ms, Ordering::Relaxed);
            } else {
                sync_rx_grace.clear();
                self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
            }
            for dir in 0..2 {
                rx[dir][0].clear();
                rx[dir][1].clear();
            }
        }

        self.key_cache
            .lock()
            .unwrap()
            .fill([EpochKeySlot::default(), EpochKeySlot::default()]);
    }

    fn hkdf_traffic_key(&self, epoch: u32, dir: SecureDatagramDirection) -> [u8; 32] {
        let root_key = self.root_key();
        let salt = [0u8; 32];
        let mut extract = HmacSha256::new_from_slice(&salt).unwrap();
        extract.update(&root_key);
        let prk = extract.finalize().into_bytes();

        let mut info = Vec::with_capacity(9 + 4 + 1);
        info.extend_from_slice(b"et-traffic");
        info.extend_from_slice(&epoch.to_be_bytes());
        info.push(dir.idx() as u8);

        let mut expand = HmacSha256::new_from_slice(&prk).unwrap();
        expand.update(&info);
        expand.update(&[1u8]);
        let okm = expand.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[..32]);
        key
    }

    fn get_or_create_encryptor(
        &self,
        epoch: u32,
        dir: SecureDatagramDirection,
        generation: u32,
        is_send: bool,
    ) -> Arc<dyn Encryptor> {
        let dir_idx = dir.idx();
        let mut guard = self.key_cache.lock().unwrap();
        for slot in guard[dir_idx].iter_mut() {
            if slot.valid && slot.epoch == epoch && slot.generation == generation {
                return slot.get_encryptor(is_send);
            }
        }

        let key = self.hkdf_traffic_key(epoch, dir);
        let mut key_128 = [0u8; 16];
        key_128.copy_from_slice(&key[..16]);

        let slot = EpochKeySlot {
            epoch,
            generation,
            valid: true,
            send_cipher: Some(create_encryptor(&self.send_cipher_algorithm, key_128, key)),
            recv_cipher: Some(create_encryptor(&self.recv_cipher_algorithm, key_128, key)),
        };
        let ret = slot.get_encryptor(is_send);

        if !guard[dir_idx][0].valid || guard[dir_idx][0].epoch == epoch {
            guard[dir_idx][0] = slot;
        } else {
            guard[dir_idx][1] = slot;
        }

        ret
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

    fn next_nonce(&self, dir: SecureDatagramDirection) -> (u32, u64, [u8; 12]) {
        let now_ms = now_ms();
        self.maybe_rotate_epoch(now_ms);
        let epoch = self.send_epoch.load(Ordering::Relaxed);
        let seq = self.send_seq[dir.idx()].fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&epoch.to_be_bytes());
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        (epoch, seq, nonce)
    }

    fn parse_tail(payload: &[u8]) -> Option<[u8; 12]> {
        let tail = StandardAeadTail::ref_from_suffix(payload)?;
        Some(tail.nonce)
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

    fn epoch_in_slots(slots: &[EpochRxSlot; 2], epoch: u32) -> bool {
        slots[0].valid && slots[0].epoch == epoch || slots[1].valid && slots[1].epoch == epoch
    }

    fn sync_rx_grace_active(&self, now_ms: u64) -> bool {
        let expires_at_ms = self.sync_rx_grace_expires_at_ms.load(Ordering::Relaxed);
        if expires_at_ms == 0 {
            return false;
        }
        if now_ms < expires_at_ms {
            return true;
        }
        self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
        false
    }

    fn prune_key_cache(
        &self,
        rx: &[[EpochRxSlot; 2]; 2],
        sync_rx_grace: Option<&SyncRxGrace>,
    ) {
        let send_epoch = self.send_epoch.load(Ordering::Relaxed);
        let mut key_cache = self.key_cache.lock().unwrap();
        for d in 0..2 {
            for s in 0..2 {
                if !key_cache[d][s].valid {
                    continue;
                }
                let e = key_cache[d][s].epoch;
                let allowed = e == send_epoch
                    || rx[d][0].valid && rx[d][0].epoch == e
                    || rx[d][1].valid && rx[d][1].epoch == e
                    || sync_rx_grace.is_some_and(|g| Self::epoch_in_slots(&g.slots[d], e));
                if !allowed {
                    key_cache[d][s].valid = false;
                }
            }
        }
    }

    fn precheck_replay(
        &self,
        epoch: u32,
        seq: u64,
        dir: SecureDatagramDirection,
        now_ms: u64,
    ) -> bool {
        let dir_idx = dir.idx();
        let mut rx = self.rx_slots.lock().unwrap();
        Self::evict_old_rx_slots(&mut rx, now_ms);
        let sync_rx_grace = if self.sync_rx_grace_active(now_ms) {
            let mut sync_rx_grace = self.sync_rx_grace.lock().unwrap();
            sync_rx_grace.maybe_expire(now_ms);
            if sync_rx_grace.valid {
                Self::evict_old_rx_slots(&mut sync_rx_grace.slots, now_ms);
                Some(sync_rx_grace)
            } else {
                self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
                None
            }
        } else {
            None
        };

        if sync_rx_grace
            .as_ref()
            .is_some_and(|g| Self::epoch_in_slots(&g.slots[dir_idx], epoch))
        {
            for slot in sync_rx_grace.as_ref().unwrap().slots[dir_idx].iter() {
                if slot.valid && slot.epoch == epoch {
                    return slot.window.can_accept(seq);
                }
            }
        }

        if !rx[dir_idx][0].valid {
            return true;
        }

        if rx[dir_idx][0].valid && epoch == rx[dir_idx][0].epoch {
            return rx[dir_idx][0].window.can_accept(seq);
        }

        if rx[dir_idx][1].valid && epoch == rx[dir_idx][1].epoch {
            return rx[dir_idx][1].window.can_accept(seq);
        }

        if rx[dir_idx][0].valid && epoch > rx[dir_idx][0].epoch {
            let mut baseline_epoch = self.send_epoch.load(Ordering::Relaxed);
            if rx[dir_idx][0].valid {
                baseline_epoch = baseline_epoch.max(rx[dir_idx][0].epoch);
            }
            if rx[dir_idx][1].valid {
                baseline_epoch = baseline_epoch.max(rx[dir_idx][1].epoch);
            }
            let max_allowed_epoch =
                baseline_epoch.saturating_add(Self::MAX_ACCEPTED_RX_EPOCH_AHEAD);
            if epoch > max_allowed_epoch {
                return false;
            }

            return true;
        }

        false
    }

    fn commit_replay(
        &self,
        epoch: u32,
        seq: u64,
        dir: SecureDatagramDirection,
        now_ms: u64,
    ) -> bool {
        let dir_idx = dir.idx();
        let mut rx = self.rx_slots.lock().unwrap();
        Self::evict_old_rx_slots(&mut rx, now_ms);
        let mut sync_rx_grace = if self.sync_rx_grace_active(now_ms) {
            let mut sync_rx_grace = self.sync_rx_grace.lock().unwrap();
            sync_rx_grace.maybe_expire(now_ms);
            if sync_rx_grace.valid {
                Self::evict_old_rx_slots(&mut sync_rx_grace.slots, now_ms);
                Some(sync_rx_grace)
            } else {
                self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
                None
            }
        } else {
            None
        };

        let accepted = if sync_rx_grace
            .as_ref()
            .is_some_and(|g| Self::epoch_in_slots(&g.slots[dir_idx], epoch))
        {
            let mut accepted = false;
            for slot in sync_rx_grace.as_mut().unwrap().slots[dir_idx].iter_mut() {
                if slot.valid && slot.epoch == epoch {
                    slot.last_rx_ms = now_ms;
                    accepted = slot.window.accept(seq);
                    break;
                }
            }
            accepted
        } else {
            if !rx[dir_idx][0].valid {
                rx[dir_idx][0] = EpochRxSlot {
                    epoch,
                    window: ReplayWindow256::default(),
                    last_rx_ms: now_ms,
                    valid: true,
                };
            }

            if rx[dir_idx][0].valid && epoch == rx[dir_idx][0].epoch {
                rx[dir_idx][0].last_rx_ms = now_ms;
                rx[dir_idx][0].window.accept(seq)
            } else if rx[dir_idx][1].valid && epoch == rx[dir_idx][1].epoch {
                rx[dir_idx][1].last_rx_ms = now_ms;
                rx[dir_idx][1].window.accept(seq)
            } else if rx[dir_idx][0].valid && epoch > rx[dir_idx][0].epoch {
                let mut baseline_epoch = self.send_epoch.load(Ordering::Relaxed);
                if rx[dir_idx][0].valid {
                    baseline_epoch = baseline_epoch.max(rx[dir_idx][0].epoch);
                }
                if rx[dir_idx][1].valid {
                    baseline_epoch = baseline_epoch.max(rx[dir_idx][1].epoch);
                }
                let max_allowed_epoch =
                    baseline_epoch.saturating_add(Self::MAX_ACCEPTED_RX_EPOCH_AHEAD);
                if epoch > max_allowed_epoch {
                    false
                } else {
                    rx[dir_idx][1] = rx[dir_idx][0];
                    rx[dir_idx][0] = EpochRxSlot {
                        epoch,
                        window: ReplayWindow256::default(),
                        last_rx_ms: now_ms,
                        valid: true,
                    };
                    rx[dir_idx][0].window.accept(seq)
                }
            } else {
                false
            }
        };

        self.prune_key_cache(&rx, sync_rx_grace.as_ref().map(|g| &**g));
        accepted
    }

    fn check_replay(
        &self,
        epoch: u32,
        seq: u64,
        dir: SecureDatagramDirection,
        now_ms: u64,
    ) -> bool {
        if self.precheck_replay(epoch, seq, dir, now_ms) {
            return self.commit_replay(epoch, seq, dir, now_ms);
        }

        false
    }

    pub fn encrypt_payload(
        &self,
        dir: SecureDatagramDirection,
        pkt: &mut ZCPacket,
    ) -> Result<(), anyhow::Error> {
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        let (epoch, _seq, nonce_bytes) = self.next_nonce(dir);
        let encryptor = self.get_or_create_encryptor(epoch, dir, self.session_generation(), true);
        if let Err(e) = encryptor.encrypt_with_nonce(pkt, Some(nonce_bytes.as_slice())) {
            tracing::warn!(?e, "secure datagram session encrypt failed, invalidating");
            self.invalidate();
            return Err(e.into());
        }
        Ok(())
    }

    pub fn decrypt_payload(
        &self,
        dir: SecureDatagramDirection,
        ciphertext_with_tail: &mut ZCPacket,
    ) -> Result<(), anyhow::Error> {
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        let nonce_bytes =
            Self::parse_tail(ciphertext_with_tail.payload()).ok_or_else(|| anyhow!("no tail"))?;
        let epoch = u32::from_be_bytes(nonce_bytes[..4].try_into().unwrap());
        let seq = u64::from_be_bytes(nonce_bytes[4..].try_into().unwrap());

        let now_ms = now_ms();
        if !self.precheck_replay(epoch, seq, dir, now_ms) {
            return Err(anyhow!("replay rejected"));
        }

        let encryptor = self.get_or_create_encryptor(epoch, dir, self.session_generation(), false);
        if let Err(e) = encryptor.decrypt(ciphertext_with_tail) {
            let count = self.decrypt_fail_count.fetch_add(1, Ordering::Relaxed) + 1;
            if count >= Self::DECRYPT_FAIL_THRESHOLD {
                self.invalidate();
                tracing::warn!(
                    count,
                    "secure datagram session auto-invalidated after consecutive decrypt failures"
                );
            }
            return Err(e.into());
        }
        self.decrypt_fail_count.store(0, Ordering::Relaxed);

        if !self.commit_replay(epoch, seq, dir, now_ms) {
            return Err(anyhow!("replay rejected"));
        }

        Ok(())
    }

    #[cfg(test)]
    fn check_replay_for_test(
        &self,
        epoch: u32,
        seq: u64,
        dir: SecureDatagramDirection,
        now_ms: u64,
    ) -> bool {
        self.check_replay(epoch, seq, dir, now_ms)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::packet_def::PacketType;

    #[test]
    fn secure_datagram_supports_asymmetric_algorithms() {
        let root_key = SecureDatagramSession::new_root_key();
        let generation = 1u32;
        let initial_epoch = 0u32;

        let ab = SecureDatagramSession::new(
            root_key,
            generation,
            initial_epoch,
            "aes-256-gcm".to_string(),
            "chacha20-poly1305".to_string(),
        );
        let ba = SecureDatagramSession::new(
            root_key,
            generation,
            initial_epoch,
            "chacha20-poly1305".to_string(),
            "aes-256-gcm".to_string(),
        );

        let plaintext1 = b"hello from a";
        let mut pkt1 = ZCPacket::new_with_payload(plaintext1);
        pkt1.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        ab.encrypt_payload(SecureDatagramDirection::AToB, &mut pkt1)
            .unwrap();
        ba.decrypt_payload(SecureDatagramDirection::AToB, &mut pkt1)
            .unwrap();
        assert_eq!(pkt1.payload(), plaintext1);

        let plaintext2 = b"hello from b";
        let mut pkt2 = ZCPacket::new_with_payload(plaintext2);
        pkt2.fill_peer_manager_hdr(20, 10, PacketType::Data as u8);
        ba.encrypt_payload(SecureDatagramDirection::BToA, &mut pkt2)
            .unwrap();
        ab.decrypt_payload(SecureDatagramDirection::BToA, &mut pkt2)
            .unwrap();
        assert_eq!(pkt2.payload(), plaintext2);
    }

    #[test]
    fn replay_rejects_far_future_epoch_without_poisoning_window() {
        let s = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let now = now_ms();

        assert!(s.check_replay_for_test(0, 1, SecureDatagramDirection::AToB, now));
        assert!(s.check_replay_for_test(0, 2, SecureDatagramDirection::AToB, now));

        assert!(!s.check_replay_for_test(1000, 1, SecureDatagramDirection::AToB, now));

        assert!(s.check_replay_for_test(1, 1, SecureDatagramDirection::AToB, now + 1));
        assert!(s.check_replay_for_test(1, 2, SecureDatagramDirection::AToB, now + 2));
    }

    #[test]
    fn failed_decrypt_does_not_poison_replay_window() {
        let root_key = SecureDatagramSession::new_root_key();
        let sender = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let receiver = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let mut pkt0 = ZCPacket::new_with_payload(b"pkt0");
        pkt0.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        sender
            .encrypt_payload(SecureDatagramDirection::AToB, &mut pkt0)
            .unwrap();
        receiver
            .decrypt_payload(SecureDatagramDirection::AToB, &mut pkt0)
            .unwrap();

        let mut forged = ZCPacket::new_with_payload(b"forged");
        forged.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        sender
            .encrypt_payload(SecureDatagramDirection::AToB, &mut forged)
            .unwrap();

        let mut poisoned_nonce = [0u8; StandardAeadTail::NONCE_SIZE];
        poisoned_nonce[..4].copy_from_slice(&0u32.to_be_bytes());
        poisoned_nonce[4..].copy_from_slice(&500u64.to_be_bytes());

        let payload = forged.mut_payload();
        let nonce_offset = payload.len() - StandardAeadTail::NONCE_SIZE;
        payload[nonce_offset..].copy_from_slice(&poisoned_nonce);

        assert!(
            receiver
                .decrypt_payload(SecureDatagramDirection::AToB, &mut forged)
                .is_err()
        );

        let plaintext = b"pkt2";
        let mut pkt2 = ZCPacket::new_with_payload(plaintext);
        pkt2.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        sender
            .encrypt_payload(SecureDatagramDirection::AToB, &mut pkt2)
            .unwrap();
        receiver
            .decrypt_payload(SecureDatagramDirection::AToB, &mut pkt2)
            .unwrap();
        assert_eq!(pkt2.payload(), plaintext);
    }

    #[test]
    fn replay_window_shift_preserves_bits() {
        let mut w = ReplayWindow256::default();
        for i in 0..10u64 {
            assert!(w.accept(i), "seq {i} should be accepted");
        }
        assert_eq!(w.max_seq, 9);

        for i in 0..10u64 {
            assert!(!w.accept(i), "seq {i} should be rejected as replay");
        }

        assert!(w.accept(10));
    }

    #[test]
    fn replay_window_out_of_order_within_window() {
        let mut w = ReplayWindow256::default();
        for i in (0..=20u64).step_by(2) {
            assert!(w.accept(i), "seq {i} should be accepted");
        }
        for i in (1..=19u64).step_by(2) {
            assert!(w.accept(i), "seq {i} should be accepted (out of order)");
        }
        for i in 0..=20u64 {
            assert!(!w.accept(i), "seq {i} should be rejected as replay");
        }
    }

    #[test]
    fn sync_root_key_allows_any_epoch_from_remote() {
        let s = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let root_key = s.root_key();
        let now = now_ms();
        assert!(s.check_replay_for_test(0, 0, SecureDatagramDirection::AToB, now));
        assert!(s.check_replay_for_test(0, 1, SecureDatagramDirection::AToB, now));

        s.sync_root_key(root_key, 2, 2, true);

        assert!(s.check_replay_for_test(0, 10, SecureDatagramDirection::AToB, now + 1));
    }

    #[test]
    fn sync_root_key_keeps_previous_epochs_during_grace_window() {
        let s = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let root_key = s.root_key();
        let now = now_ms();
        assert!(s.check_replay_for_test(0, 0, SecureDatagramDirection::AToB, now));
        assert!(s.check_replay_for_test(1, 0, SecureDatagramDirection::AToB, now + 1));

        s.sync_root_key(root_key, 2, 2, true);

        assert!(s.check_replay_for_test(2, 0, SecureDatagramDirection::AToB, now + 2));
        assert!(s.check_replay_for_test(1, 1, SecureDatagramDirection::AToB, now + 3));
        assert!(s.check_replay_for_test(0, 1, SecureDatagramDirection::AToB, now + 4));
    }

    #[test]
    fn sync_root_key_expires_previous_epochs_after_grace_window() {
        let s = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let root_key = s.root_key();
        let now = now_ms();
        assert!(s.check_replay_for_test(0, 0, SecureDatagramDirection::AToB, now));
        assert!(s.check_replay_for_test(1, 0, SecureDatagramDirection::AToB, now + 1));

        s.sync_root_key(root_key, 2, 2, true);
        assert!(s.check_replay_for_test(2, 0, SecureDatagramDirection::AToB, now + 2));

        assert!(!s.check_replay_for_test(
            0,
            1,
            SecureDatagramDirection::AToB,
            now + SecureDatagramSession::SYNC_RX_GRACE_AFTER_MS + 3
        ));
    }

    #[test]
    fn sync_root_key_does_not_preserve_previous_epochs_when_root_key_changes() {
        let s = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let now = now_ms();
        assert!(s.check_replay_for_test(0, 0, SecureDatagramDirection::AToB, now));
        assert!(s.check_replay_for_test(1, 0, SecureDatagramDirection::AToB, now + 1));

        s.sync_root_key(SecureDatagramSession::new_root_key(), 2, 2, true);
        assert!(s.check_replay_for_test(2, 0, SecureDatagramDirection::AToB, now + 2));
        assert!(!s.check_replay_for_test(1, 1, SecureDatagramDirection::AToB, now + 3));
    }
}
