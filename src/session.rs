use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::carrier::Batch;
use super::crypto::{self, Jitter, Keys, Rx};
use super::handshake::Params;
use super::wire::{self, Frame, Stat};
use super::Carrier;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Dialer,
    Responder,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub ping: Duration,
    pub idle: Duration,
    pub ring: usize,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            ping: Duration::from_secs(1),
            idle: Duration::from_secs(30),
            ring: 256,
        }
    }
}

pub fn now_us() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_micros() as u64
}

pub const PROBE_FLOOR: usize = 508;
pub const PROBE_TRIES: usize = 3;
pub const PROBE_WAIT: Duration = Duration::from_millis(200);
pub const PROBE_ROUNDS: usize = 6;
pub const PROBE_RETRIES: usize = 8;

pub struct Mtu {
    payload: AtomicUsize,
    assumed: usize,
    probed: AtomicBool,
    ack: AtomicU64,
    seq: AtomicU32,
}

impl Mtu {
    fn new(assumed: usize) -> Mtu {
        Mtu {
            payload: AtomicUsize::new(assumed),
            assumed,
            probed: AtomicBool::new(false),
            ack: AtomicU64::new(0),
            seq: AtomicU32::new(0),
        }
    }

    pub fn payload(&self) -> usize {
        self.payload.load(Relaxed)
    }

    pub fn assumed(&self) -> usize {
        self.assumed
    }

    pub fn probed(&self) -> bool {
        self.probed.load(Relaxed)
    }

    fn cap(&self, to: usize) {
        if to >= PROBE_FLOOR {
            self.payload.fetch_min(to, Relaxed);
        }
    }

    fn record(&self, seq: u16, payload: u16) {
        self.ack
            .fetch_max((u64::from(seq) << 16) | u64::from(payload), Relaxed);
    }

    fn newest(&self) -> (u16, u16) {
        let v = self.ack.load(Relaxed);
        ((v >> 16) as u16, v as u16)
    }
}

enum Round {
    Fits,
    TooBig,
    NoSignal,
}

pub fn too_big(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::EMSGSIZE)
}

struct Ring<T> {
    q: Mutex<VecDeque<T>>,
    cap: usize,
    wake: Notify,
    dropped: AtomicU64,
    closed: Mutex<bool>,
}

impl<T> Ring<T> {
    fn new(cap: usize) -> Ring<T> {
        Ring {
            q: Mutex::new(VecDeque::with_capacity(cap.min(1024))),
            cap: cap.max(1),
            wake: Notify::new(),
            dropped: AtomicU64::new(0),
            closed: Mutex::new(false),
        }
    }

    fn push(&self, v: T) {
        {
            let mut q = self.q.lock().unwrap();
            if q.len() >= self.cap {
                q.pop_front();
                self.dropped.fetch_add(1, Relaxed);
            }
            q.push_back(v);
        }
        self.wake.notify_one();
    }

    fn try_pop(&self) -> Option<T> {
        self.q.lock().unwrap().pop_front()
    }

    async fn wait(&self) {
        self.wake.notified().await
    }

    fn close(&self) {
        *self.closed.lock().unwrap() = true;
        self.wake.notify_waiters();
    }

    fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap()
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Relaxed)
    }
}

#[derive(Default)]
pub struct Stats {
    pub tx_datagrams: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub tx_errors: AtomicU64,
    pub rx_datagrams: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub rejected: AtomicU64,
    pub lost: AtomicU64,
    pub highest: AtomicU64,
    pub reordered: AtomicU64,
    pub duplicates: AtomicU64,
    pub jitter_us: AtomicU32,
    pub rtt_us: AtomicU32,
    pub peer_lost: AtomicU64,
    pub peer_recv: AtomicU64,
    pub peer_jitter_us: AtomicU32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub tx_datagrams: u64,
    pub tx_bytes: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
    pub rx_datagrams: u64,
    pub rx_bytes: u64,
    pub rx_dropped: u64,
    pub rejected: u64,
    pub lost: u64,
    pub highest: u64,
    pub reordered: u64,
    pub duplicates: u64,
    pub jitter_us: u32,
    pub rtt_us: u32,
    pub peer_lost: u64,
    pub peer_recv: u64,
    pub peer_jitter_us: u32,
}

impl Snapshot {
    pub fn loss_ratio(&self) -> f64 {
        if self.highest == 0 {
            return 0.0;
        }
        self.lost as f64 / self.highest as f64
    }

    pub fn peer_loss_ratio(&self) -> f64 {
        let sent = self.peer_lost + self.peer_recv;
        if sent == 0 {
            return 0.0;
        }
        self.peer_lost as f64 / sent as f64
    }
}

pub struct Handle {
    out: Arc<Ring<Vec<u8>>>,
    inbox: Arc<Ring<(u16, Vec<u8>)>>,
    stats: Arc<Stats>,
    mtu: Arc<Mtu>,
}

impl Handle {
    pub fn send(&self, flow: u16, payload: &[u8]) {
        let mut inner = Vec::with_capacity(payload.len() + wire::DATA_HDR);
        Frame::Data { flow, payload }.write(&mut inner);
        self.out.push(inner);
    }

    pub async fn recv(&self) -> Option<(u16, Vec<u8>)> {
        loop {
            if let Some(v) = self.inbox.try_pop() {
                return Some(v);
            }
            if self.inbox.is_closed() {
                return None;
            }
            self.inbox.wait().await;
        }
    }

    pub async fn recv_batch(&self, out: &mut Vec<(u16, Vec<u8>)>, max: usize) -> usize {
        out.clear();
        loop {
            while out.len() < max.max(1) {
                match self.inbox.try_pop() {
                    Some(v) => out.push(v),
                    None => break,
                }
            }
            if !out.is_empty() {
                return out.len();
            }
            if self.inbox.is_closed() {
                return 0;
            }
            self.inbox.wait().await;
        }
    }

    pub fn payload_mtu(&self) -> usize {
        self.mtu.payload()
    }

    pub fn mtu(&self) -> &Mtu {
        &self.mtu
    }

    pub async fn mtu_settled(&self) -> usize {
        let budget =
            Instant::now() + PROBE_WAIT * (PROBE_ROUNDS + PROBE_RETRIES + 3).max(1) as u32;
        while !self.mtu.probed() && Instant::now() < budget && !self.inbox.is_closed() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.mtu.payload()
    }

    pub fn snapshot(&self) -> Snapshot {
        let s = &self.stats;
        Snapshot {
            tx_datagrams: s.tx_datagrams.load(Relaxed),
            tx_bytes: s.tx_bytes.load(Relaxed),
            tx_errors: s.tx_errors.load(Relaxed),
            tx_dropped: self.out.dropped(),
            rx_datagrams: s.rx_datagrams.load(Relaxed),
            rx_bytes: s.rx_bytes.load(Relaxed),
            rx_dropped: self.inbox.dropped(),
            rejected: s.rejected.load(Relaxed),
            lost: s.lost.load(Relaxed),
            highest: s.highest.load(Relaxed),
            reordered: s.reordered.load(Relaxed),
            duplicates: s.duplicates.load(Relaxed),
            jitter_us: s.jitter_us.load(Relaxed),
            rtt_us: s.rtt_us.load(Relaxed),
            peer_lost: s.peer_lost.load(Relaxed),
            peer_recv: s.peer_recv.load(Relaxed),
            peer_jitter_us: s.peer_jitter_us.load(Relaxed),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.inbox.is_closed()
    }
}

pub struct Handshake {
    pub first: Vec<u8>,
    pub reply: Vec<u8>,
}

const RESTART_GRACE: Duration = Duration::from_secs(2);

pub fn start(
    carrier: Arc<dyn Carrier>,
    keys: Keys,
    params: Params,
    role: Role,
    cfg: Config,
    hs: Option<Handshake>,
) -> Handle {
    let parts = Parts {
        carrier,
        keys: Arc::new(keys),
        stats: Arc::new(Stats::default()),
        out: Arc::new(Ring::new(cfg.ring)),
        inbox: Arc::new(Ring::new(cfg.ring)),
        mtu: Arc::new(Mtu::new(params.payload_mtu as usize)),
    };
    let handle = Handle {
        out: parts.out.clone(),
        inbox: parts.inbox.clone(),
        stats: parts.stats.clone(),
        mtu: parts.mtu.clone(),
    };
    tokio::spawn(send_loop(parts.clone(), cfg, role));
    tokio::spawn(probe_loop(parts.clone()));
    tokio::spawn(recv_loop(parts, cfg, hs));
    handle
}

#[derive(Clone)]
struct Parts {
    carrier: Arc<dyn Carrier>,
    keys: Arc<Keys>,
    stats: Arc<Stats>,
    out: Arc<Ring<Vec<u8>>>,
    inbox: Arc<Ring<(u16, Vec<u8>)>>,
    mtu: Arc<Mtu>,
}

async fn probe_loop(parts: Parts) {
    let Parts {
        out,
        inbox,
        mtu,
        ..
    } = parts;
    let mtu = &mtu;
    let ceiling = mtu.assumed();
    if ceiling <= PROBE_FLOOR {
        mtu.probed.store(true, Relaxed);
        return;
    }

    let send = |size: usize| -> u16 {
        let seq = (mtu.seq.fetch_add(1, Relaxed) + 1) as u16;
        let fill = vec![0u8; wire::probe_fill(size)];
        for _ in 0..PROBE_TRIES {
            let mut inner = Vec::with_capacity(wire::PROBE_HDR + fill.len());
            Frame::Probe {
                seq,
                payload: size as u16,
                fill: &fill,
            }
            .write(&mut inner);
            out.push(inner);
        }
        seq
    };

    let (mut lo, mut hi) = (0usize, ceiling + 1);
    let mut rounds = PROBE_ROUNDS;
    let mut retries = PROBE_RETRIES;
    let mut candidate = ceiling;
    let mut doubted: Option<usize> = None;

    while !inbox.is_closed() {
        let control = send(PROBE_FLOOR);
        let probe = send(candidate);
        tokio::time::sleep(PROBE_WAIT).await;
        let (seen, _) = mtu.newest();
        let outcome = if seen >= probe {
            Round::Fits
        } else if seen >= control {
            Round::TooBig
        } else {
            Round::NoSignal
        };
        match outcome {
            Round::Fits => {
                doubted = None;
                lo = candidate;
                mtu.payload.store(lo.min(ceiling), Relaxed);
                if candidate == ceiling || hi - lo <= 1 {
                    break;
                }
            }
            Round::TooBig if doubted != Some(candidate) => {
                doubted = Some(candidate);
                if retries == 0 {
                    break;
                }
                retries -= 1;
                continue;
            }
            Round::TooBig => {
                doubted = None;
                hi = candidate;
                if hi.saturating_sub(lo.max(PROBE_FLOOR)) <= 1 {
                    break;
                }
            }
            Round::NoSignal => {
                if retries == 0 {
                    break;
                }
                retries -= 1;
                continue;
            }
        }
        if rounds == 0 {
            break;
        }
        rounds -= 1;
        let bottom = lo.max(PROBE_FLOOR);
        candidate = bottom + (hi.saturating_sub(bottom)) / 2;
        if candidate <= bottom || candidate >= hi {
            break;
        }
    }

    if lo > 0 {
        mtu.payload.store(lo.min(ceiling), Relaxed);
    }
    mtu.probed.store(true, Relaxed);
}

async fn send_loop(parts: Parts, cfg: Config, role: Role) {
    let Parts {
        carrier,
        keys,
        stats,
        out,
        inbox,
        ..
    } = parts;
    let mut dg = Vec::with_capacity(1500);
    let stride = carrier.mtu() + crypto::Keys::overhead();
    let mut batch = Batch::new(carrier.batch_size(), stride);
    let mut ping = tokio::time::interval(cfg.ping);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        loop {
            batch.clear();
            let mut oversized: Option<Vec<u8>> = None;
            while !batch.is_full() {
                let Some(inner) = out.try_pop() else { break };
                keys.seal(&inner, &mut dg);
                if !batch.push(&dg) {
                    oversized = Some(dg.clone());
                    break;
                }
            }
            if batch.is_empty() && oversized.is_none() {
                break;
            }
            if !batch.is_empty() {
                let bytes: u64 = batch.iter().map(|d| d.len() as u64).sum();
                match carrier.send_batch(&batch).await {
                    Ok(n) => {
                        stats.tx_datagrams.fetch_add(n as u64, Relaxed);
                        stats.tx_bytes.fetch_add(bytes, Relaxed);
                    }
                    Err(e) => {
                        stats.tx_errors.fetch_add(1, Relaxed);
                        if !too_big(&e) {
                            inbox.close();
                            return;
                        }
                    }
                }
            }
            if let Some(one) = oversized {
                match carrier.send(&one).await {
                    Ok(()) => {
                        stats.tx_datagrams.fetch_add(1, Relaxed);
                        stats.tx_bytes.fetch_add(one.len() as u64, Relaxed);
                    }
                    Err(e) => {
                        stats.tx_errors.fetch_add(1, Relaxed);
                        if !too_big(&e) {
                            inbox.close();
                            return;
                        }
                    }
                }
            }
        }
        if inbox.is_closed() {
            return;
        }
        tokio::select! {
            _ = out.wait() => {}
            _ = ping.tick() => {
                if role == Role::Dialer {
                    let mut inner = Vec::with_capacity(9);
                    Frame::Ping { tx_ts: now_us() }.write(&mut inner);
                    out.push(inner);
                }
                let mut st = Vec::with_capacity(21);
                let s = &*stats;
                Frame::Stat(Stat {
                    recv: s.highest.load(Relaxed).saturating_sub(s.lost.load(Relaxed)),
                    lost: s.lost.load(Relaxed),
                    jitter_us: s.jitter_us.load(Relaxed),
                })
                .write(&mut st);
                out.push(st);
            }
        }
    }
}

async fn recv_loop(parts: Parts, cfg: Config, hs: Option<Handshake>) {
    let Parts {
        carrier,
        keys,
        stats,
        out,
        inbox,
        mtu,
    } = parts;
    let mut buf = vec![0u8; 2048];
    let mut rx = Rx::new();
    let mut jitter = Jitter::new();
    let mut prev = (0u64, 0u64);
    let mut deadline = Instant::now() + cfg.idle;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let n = match tokio::time::timeout(left, carrier.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => break,
        };
        if wire::is_handshake(&buf[..n]) {
            if let (Some(h), Some((wire::HS_MSG1, _))) =
                (hs.as_ref(), wire::parse_handshake(&buf[..n]))
            {
                if buf[..n] == h.first[..] {
                    let _ = carrier.send(&h.reply).await;
                } else {
                    deadline = deadline.min(Instant::now() + RESTART_GRACE);
                }
            }
            continue;
        }
        let Some((ctr, len)) = keys.open(&mut buf[..n]) else {
            stats.rejected.fetch_add(1, Relaxed);
            continue;
        };
        deadline = Instant::now() + cfg.idle;
        if !rx.accept(ctr) {
            stats.rejected.fetch_add(1, Relaxed);
            stats.duplicates.store(rx.duplicates, Relaxed);
            continue;
        }
        stats.rx_datagrams.fetch_add(1, Relaxed);
        stats.rx_bytes.fetch_add(n as u64, Relaxed);
        stats.lost.store(rx.lost(), Relaxed);
        stats.highest.store(rx.highest(), Relaxed);
        stats.reordered.store(rx.reordered, Relaxed);

        let inner = Keys::inner(&buf[..n], len);
        match Frame::parse(inner) {
            Some(Frame::Data { flow, payload }) => {
                if payload.len() > mtu.assumed() {
                    let mut big = Vec::with_capacity(3);
                    Frame::TooBig {
                        mtu: mtu.assumed().min(u16::MAX as usize) as u16,
                    }
                    .write(&mut big);
                    out.push(big);
                }
                inbox.push((flow, payload.to_vec()));
            }
            Some(Frame::Probe { seq, payload, .. }) => {
                let mut ack = Vec::with_capacity(wire::PROBE_HDR);
                Frame::ProbeAck { seq, payload }.write(&mut ack);
                out.push(ack);
            }
            Some(Frame::ProbeAck { seq, payload }) => mtu.record(seq, payload),
            Some(Frame::TooBig { mtu: cap }) => mtu.cap(cap as usize),
            Some(Frame::Ping { tx_ts }) => {
                let rx_ts = now_us();
                jitter.sample(tx_ts as i64, rx_ts as i64);
                stats.jitter_us.store(jitter.micros(), Relaxed);
                let mut pong = Vec::with_capacity(17);
                Frame::Pong {
                    echo_ts: tx_ts,
                    rx_ts,
                }
                .write(&mut pong);
                out.push(pong);
            }
            Some(Frame::Pong { echo_ts, rx_ts }) => {
                stats
                    .rtt_us
                    .store(now_us().saturating_sub(echo_ts) as u32, Relaxed);
                jitter.sample(rx_ts as i64, now_us() as i64);
                stats.jitter_us.store(jitter.micros(), Relaxed);
            }
            Some(Frame::Stat(s)) => {
                stats.peer_lost.store(s.lost, Relaxed);
                stats.peer_recv.store(s.recv, Relaxed);
                stats.peer_jitter_us.store(s.jitter_us, Relaxed);
                if let Some(p) = carrier.pacer() {
                    let lost = s.lost.saturating_sub(prev.0);
                    let recv = s.recv.saturating_sub(prev.1);
                    if lost + recv > 0 && s.lost >= prev.0 && s.recv >= prev.1 {
                        p.observe(lost as f64 / (lost + recv) as f64);
                    }
                    prev = (s.lost, s.recv);
                }
            }
            _ => {}
        }
    }
    inbox.close();
    out.close();
}
