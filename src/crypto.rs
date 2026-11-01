use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

use super::wire::{Cid, HEAD, OVERHEAD, TAG};

pub const REPLAY_WINDOW: u64 = 128;

struct Dir {
    key: LessSafeKey,
    prefix: [u8; 4],
}

impl Dir {
    fn new(k: &[u8; 32]) -> Dir {
        let key =
            LessSafeKey::new(UnboundKey::new(&AES_256_GCM, k).expect("AES-256 key is 32 bytes"));
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&blake3::derive_key("shabdiz-v1 nonce-prefix", k)[..4]);
        Dir { key, prefix }
    }

    fn nonce(&self, ctr: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.prefix);
        n[4..].copy_from_slice(&ctr.to_be_bytes());
        Nonce::assume_unique_for_key(n)
    }
}

pub struct Keys {
    pub cid: Cid,
    send: Dir,
    recv: Dir,
    ctr: AtomicU64,
}

impl Keys {
    pub fn new(cid: Cid, i2r: [u8; 32], r2i: [u8; 32], initiator: bool) -> Keys {
        let (s, r) = if initiator { (i2r, r2i) } else { (r2i, i2r) };
        Keys {
            cid,
            send: Dir::new(&s),
            recv: Dir::new(&r),
            ctr: AtomicU64::new(0),
        }
    }

    pub fn seal(&self, inner: &[u8], out: &mut Vec<u8>) -> u64 {
        let ctr = self.ctr.fetch_add(1, Relaxed) + 1;
        out.clear();
        out.reserve(OVERHEAD + inner.len());
        out.extend_from_slice(&self.cid);
        out.extend_from_slice(&ctr.to_be_bytes());
        out.extend_from_slice(inner);
        let mut aad = [0u8; HEAD];
        aad.copy_from_slice(&out[..HEAD]);
        let tag = self
            .send
            .key
            .seal_in_place_separate_tag(self.send.nonce(ctr), Aad::from(&aad), &mut out[HEAD..])
            .expect("sealing in place cannot fail");
        out.extend_from_slice(tag.as_ref());
        ctr
    }

    pub fn open(&self, buf: &mut [u8]) -> Option<(u64, usize)> {
        if buf.len() < OVERHEAD {
            return None;
        }
        let head = super::wire::Head::parse(buf)?;
        if head.cid != self.cid {
            return None;
        }
        let mut aad = [0u8; HEAD];
        aad.copy_from_slice(&buf[..HEAD]);
        let plain = self
            .recv
            .key
            .open_in_place(self.recv.nonce(head.ctr), Aad::from(&aad), &mut buf[HEAD..])
            .ok()?;
        Some((head.ctr, plain.len()))
    }

    pub fn inner(buf: &[u8], len: usize) -> &[u8] {
        &buf[HEAD..HEAD + len]
    }

    pub const fn overhead() -> usize {
        OVERHEAD
    }

    pub const fn tag() -> usize {
        TAG
    }
}

#[derive(Debug, Default)]
pub struct Rx {
    highest: u64,
    window: u128,
    pub accepted: u64,
    pub duplicates: u64,
    pub reordered: u64,
    pub too_old: u64,
}

impl Rx {
    pub fn new() -> Rx {
        Rx::default()
    }

    pub fn accept(&mut self, ctr: u64) -> bool {
        if ctr == 0 {
            return false;
        }
        if ctr > self.highest {
            let step = ctr - self.highest;
            self.window = if step >= REPLAY_WINDOW {
                1
            } else {
                (self.window << step) | 1
            };
            self.highest = ctr;
            self.accepted += 1;
            return true;
        }
        let back = self.highest - ctr;
        if back >= REPLAY_WINDOW {
            self.too_old += 1;
            return false;
        }
        let bit = 1u128 << back;
        if self.window & bit != 0 {
            self.duplicates += 1;
            return false;
        }
        self.window |= bit;
        self.accepted += 1;
        self.reordered += 1;
        true
    }

    pub fn lost(&self) -> u64 {
        self.highest.saturating_sub(self.accepted)
    }

    pub fn loss_ratio(&self) -> f64 {
        if self.highest == 0 {
            return 0.0;
        }
        self.lost() as f64 / self.highest as f64
    }

    pub fn highest(&self) -> u64 {
        self.highest
    }
}

#[derive(Debug, Default)]
pub struct Jitter {
    last: Option<i64>,
    smoothed_us: f64,
}

impl Jitter {
    pub fn new() -> Jitter {
        Jitter::default()
    }

    pub fn sample(&mut self, tx_us: i64, rx_us: i64) {
        let offset = rx_us - tx_us;
        if let Some(prev) = self.last {
            let d = (offset - prev).unsigned_abs() as f64;
            self.smoothed_us += (d - self.smoothed_us) / 16.0;
        }
        self.last = Some(offset);
    }

    pub fn micros(&self) -> u32 {
        self.smoothed_us as u32
    }
}
