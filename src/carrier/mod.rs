use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;

#[cfg(target_os = "linux")]
pub mod esp;
#[cfg(target_os = "linux")]
pub mod gre;
#[cfg(target_os = "linux")]
pub mod l2;
#[cfg(target_os = "linux")]
pub mod l2frame;
#[cfg(target_os = "linux")]
pub(crate) mod rawfd;
#[cfg(target_os = "linux")]
pub mod rawip;
#[cfg(target_os = "linux")]
pub mod tagged;
pub mod tcp;
#[cfg(target_os = "linux")]
mod txtime;
pub mod udp;

pub const BATCH: usize = 32;

#[async_trait]
pub trait Carrier: Send + Sync {
    async fn send(&self, datagram: &[u8]) -> std::io::Result<()>;
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn mtu(&self) -> usize;

    async fn send_batch(&self, batch: &Batch) -> std::io::Result<usize> {
        let mut n = 0;
        for d in batch.iter() {
            self.send(d).await?;
            n += 1;
        }
        Ok(n)
    }

    async fn recv_batch(&self, batch: &mut Batch) -> std::io::Result<usize> {
        batch.clear();
        let Some(slot) = batch.push_uninit(self.mtu()) else {
            return Ok(0);
        };
        let n = self.recv(slot).await?;
        batch.commit_last(n);
        Ok(1)
    }

    fn batch_size(&self) -> usize {
        1
    }

    fn kernel_paced(&self) -> bool {
        false
    }

    fn pacer(&self) -> Option<&Pacer> {
        None
    }
}

pub struct Pacer {
    burst: AtomicUsize,
    manual: AtomicBool,
    gap_us: AtomicUsize,
    rate_pps: AtomicUsize,
    next_us: Mutex<u64>,
    sent: AtomicU64,
    window_us: AtomicU64,
    last_cut_us: AtomicU64,
    auto_rate: AtomicBool,
    loss_ppm: AtomicU32,
}

fn now_us() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_micros() as u64
}

const SLEEP_FLOOR_US: u64 = 1_500;

const CREDIT_US: u64 = 2_000;

const LOSSY: f64 = 0.05;
const CLEAN: f64 = 0.03;

const COOLDOWN_US: u64 = 3_000_000;

const MIN_PPS: usize = 500;

pub const SAFE_BURST: usize = 2;

impl Pacer {
    pub fn new(burst: usize) -> Pacer {
        Pacer {
            burst: AtomicUsize::new(burst.max(1)),
            manual: AtomicBool::new(false),
            gap_us: AtomicUsize::new(0),
            rate_pps: AtomicUsize::new(0),
            next_us: Mutex::new(0),
            sent: AtomicU64::new(0),
            window_us: AtomicU64::new(now_us()),
            last_cut_us: AtomicU64::new(0),
            loss_ppm: AtomicU32::new(0),
            auto_rate: AtomicBool::new(false),
        }
    }

    pub fn burst(&self) -> usize {
        self.burst.load(Relaxed).max(1)
    }

    pub fn set_burst(&self, n: usize) {
        self.burst.store(n.clamp(1, BATCH), Relaxed);
    }

    pub fn enable_auto_rate(&self) {
        self.auto_rate.store(true, Relaxed);
    }

    pub fn set_manual(&self) {
        self.manual.store(true, Relaxed);
    }

    pub fn set_gap(&self, gap: Duration) {
        self.gap_us.store(gap.as_micros() as usize, Relaxed);
    }

    pub fn rate_pps(&self) -> usize {
        self.rate_pps.load(Relaxed)
    }

    pub fn set_rate_pps(&self, pps: usize) {
        self.rate_pps.store(pps, Relaxed);
    }

    pub fn achieved_pps(&self) -> usize {
        let elapsed = now_us().saturating_sub(self.window_us.load(Relaxed));
        if elapsed < 200_000 {
            return 0;
        }
        (self.sent.load(Relaxed) * 1_000_000 / elapsed) as usize
    }

    pub async fn admit(&self, datagrams: usize) -> Option<u64> {
        self.sent.fetch_add(datagrams as u64, Relaxed);
        let rate = self.rate_pps.load(Relaxed) as u64;
        let gap = self.gap_us.load(Relaxed) as u64;
        if rate == 0 && gap == 0 {
            return None;
        }
        let by_rate = (datagrams as u64 * 1_000_000)
            .checked_div(rate)
            .unwrap_or(0);
        let cost = by_rate.max(gap);
        let now = now_us();
        let wait = {
            let mut next = self.next_us.lock().unwrap_or_else(|e| e.into_inner());
            let due = (*next).max(now.saturating_sub(CREDIT_US));
            *next = due + cost;
            due.saturating_sub(now)
        };
        if wait >= SLEEP_FLOOR_US {
            tokio::time::sleep(Duration::from_micros(wait)).await;
            return None;
        }
        match wait {
            0 => None,
            us => Some(us * 1_000),
        }
    }

    fn cut_is_due(&self, now: u64) -> bool {
        let last = self.last_cut_us.load(Relaxed);
        last == 0 || now.saturating_sub(last) >= COOLDOWN_US
    }

    pub fn observe(&self, loss_ratio: f64) {
        if self.manual.load(Relaxed) {
            return;
        }
        let pps = self.achieved_pps();
        let cur = self.burst();
        let now = now_us();
        let ppm = ((loss_ratio.clamp(0.0, 1.0) * 1e6) as u32 / 2)
            .saturating_add(self.loss_ppm.load(Relaxed) / 2);
        self.loss_ppm.store(ppm, Relaxed);
        let loss_ratio = f64::from(ppm) / 1e6;
        if loss_ratio > LOSSY {
            if cur > SAFE_BURST {
                self.set_burst((cur / 2).max(SAFE_BURST));
            } else if self.auto_rate.load(Relaxed) && pps > 0 && self.cut_is_due(now) {
                let want = ((pps as f64 * 0.75) as usize).max(MIN_PPS);
                let rate = self.rate_pps.load(Relaxed);
                self.rate_pps
                    .store(if rate == 0 { want } else { rate.min(want) }, Relaxed);
                self.last_cut_us.store(now.max(1), Relaxed);
            }
        } else if loss_ratio < CLEAN {
            let rate = self.rate_pps.load(Relaxed);
            if rate > 0 {
                if self.auto_rate.load(Relaxed) && pps > 0 {
                    let next = rate + rate / 8 + 1;
                    self.rate_pps
                        .store(if next > pps * 2 { 0 } else { next }, Relaxed);
                }
            } else if cur < BATCH {
                self.set_burst(cur + 1);
            }
        }
        self.sent.store(0, Relaxed);
        self.window_us.store(now_us(), Relaxed);
    }
}

impl Default for Pacer {
    fn default() -> Pacer {
        Pacer::new(SAFE_BURST)
    }
}

pub struct Batch {
    buf: Vec<u8>,
    lens: Vec<usize>,
    stride: usize,
    cap: usize,
}

impl Batch {
    pub fn new(cap: usize, stride: usize) -> Batch {
        let (cap, stride) = (cap.max(1), stride.max(1));
        Batch {
            buf: vec![0; cap * stride],
            lens: Vec::with_capacity(cap),
            stride,
            cap,
        }
    }

    pub fn clear(&mut self) {
        self.lens.clear();
    }

    pub fn len(&self) -> usize {
        self.lens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lens.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.lens.len() >= self.cap
    }

    pub fn stride(&self) -> usize {
        self.stride
    }

    pub fn push(&mut self, d: &[u8]) -> bool {
        if self.is_full() || d.len() > self.stride {
            return false;
        }
        let at = self.lens.len() * self.stride;
        self.buf[at..at + d.len()].copy_from_slice(d);
        self.lens.push(d.len());
        true
    }

    pub fn push_uninit(&mut self, want: usize) -> Option<&mut [u8]> {
        if self.is_full() || want > self.stride {
            return None;
        }
        let at = self.lens.len() * self.stride;
        self.lens.push(0);
        Some(&mut self.buf[at..at + want])
    }

    pub fn commit_last(&mut self, n: usize) {
        if let Some(last) = self.lens.last_mut() {
            *last = n.min(self.stride);
        }
    }

    pub fn drop_last(&mut self) {
        self.lens.pop();
    }

    pub fn get(&self, i: usize) -> Option<&[u8]> {
        let len = *self.lens.get(i)?;
        let at = i * self.stride;
        Some(&self.buf[at..at + len])
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        (0..self.lens.len()).filter_map(move |i| self.get(i))
    }

    pub fn is_gso_shaped(&self) -> bool {
        match self.lens.split_last() {
            None | Some((_, [])) => true,
            Some((last, head)) => {
                let first = head[0];
                head.iter().all(|&l| l == first) && *last <= first
            }
        }
    }

    pub fn gso_payload<'a>(&self, scratch: &'a mut Vec<u8>) -> Option<(usize, &'a [u8])> {
        if !self.is_gso_shaped() || self.lens.is_empty() {
            return None;
        }
        let seg = self.lens[0];
        scratch.clear();
        scratch.reserve(self.lens.iter().sum());
        for d in self.iter() {
            scratch.extend_from_slice(d);
        }
        Some((seg, &scratch[..]))
    }

    pub fn groups(&self, n: usize) -> impl Iterator<Item = (usize, usize)> + '_ {
        let (len, n) = (self.lens.len(), n.max(1));
        (0..len)
            .step_by(n)
            .map(move |start| (start, (start + n).min(len)))
    }

    pub fn group_payload<'a>(
        &self,
        range: (usize, usize),
        scratch: &'a mut Vec<u8>,
    ) -> Option<(usize, &'a [u8])> {
        let (from, to) = range;
        let lens = self.lens.get(from..to)?;
        let (last, head) = lens.split_last()?;
        let seg = *head.first().unwrap_or(last);
        if !head.iter().all(|&l| l == seg) || *last > seg || seg == 0 {
            return None;
        }
        scratch.clear();
        for i in from..to {
            scratch.extend_from_slice(self.get(i)?);
        }
        Some((seg, &scratch[..]))
    }

    pub fn split_coalesced(&mut self, data: &[u8], seg: usize) -> usize {
        self.clear();
        if seg == 0 {
            return 0;
        }
        let mut n = 0;
        for chunk in data.chunks(seg) {
            if !self.push(chunk) {
                break;
            }
            n += 1;
        }
        n
    }
}
