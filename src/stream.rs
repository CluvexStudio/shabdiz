use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use crate::wire::{AckRange, Frame, StreamKind, SACK_RANGES};

pub const MAX_INFLIGHT: usize = 512 * 1024;

pub const MAX_REASSEMBLY: usize = 512 * 1024;

pub const MIN_RTO: Duration = Duration::from_millis(120);
pub const MAX_RTO: Duration = Duration::from_secs(8);

pub const MAX_RETRIES: u16 = 12;

struct Chunk {
    off: u64,
    data: Vec<u8>,
    sent_at: Instant,
    retries: u16,
}

impl Chunk {
    fn end(&self) -> u64 {
        self.off + self.data.len() as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Open,
    PeerFinished,
    Dead,
}

pub struct Stream {
    pub sid: u32,
    pub kind: StreamKind,
    state: State,

    write_off: u64,
    queue: VecDeque<Chunk>,
    inflight: usize,
    peer_ack: u64,
    fin_at: Option<u64>,

    read_off: u64,
    holes: BTreeMap<u64, Vec<u8>>,
    held: usize,
    peer_fin_at: Option<u64>,

    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
}

impl Stream {
    pub fn new(sid: u32, kind: StreamKind) -> Stream {
        Stream {
            sid,
            kind,
            state: State::Open,
            write_off: 0,
            queue: VecDeque::new(),
            inflight: 0,
            peer_ack: 0,
            fin_at: None,
            read_off: 0,
            holes: BTreeMap::new(),
            held: 0,
            peer_fin_at: None,
            srtt: None,
            rttvar: Duration::ZERO,
            rto: MIN_RTO,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn inflight(&self) -> usize {
        self.inflight
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }

    pub fn writable(&self) -> usize {
        MAX_INFLIGHT.saturating_sub(self.inflight)
    }

    pub fn write(
        &mut self,
        data: &[u8],
        mss: usize,
        now: Instant,
        out: &mut Vec<Vec<u8>>,
    ) -> usize {
        if self.state == State::Dead || mss == 0 {
            return 0;
        }
        let room = self.writable().min(data.len());
        let mut done = 0;
        while done < room {
            let n = mss.min(room - done);
            let off = self.write_off;
            let chunk = Chunk {
                off,
                data: data[done..done + n].to_vec(),
                sent_at: now,
                retries: 0,
            };
            out.push(encode_data(self.sid, off, &chunk.data));
            self.write_off += n as u64;
            self.inflight += n;
            self.queue.push_back(chunk);
            done += n;
        }
        done
    }

    pub fn finish(&mut self, out: &mut Vec<Vec<u8>>) {
        if self.fin_at.is_some() || self.state == State::Dead {
            return;
        }
        self.fin_at = Some(self.write_off);
        let mut f = Vec::with_capacity(13);
        Frame::SFin {
            sid: self.sid,
            final_off: self.write_off,
        }
        .write(&mut f);
        out.push(f);
    }

    pub fn reset(&mut self, code: u8, out: &mut Vec<Vec<u8>>) {
        self.state = State::Dead;
        self.queue.clear();
        self.inflight = 0;
        let mut f = Vec::with_capacity(6);
        Frame::SRst {
            sid: self.sid,
            code,
        }
        .write(&mut f);
        out.push(f);
    }

    pub fn on_ack(
        &mut self,
        ack_to: u64,
        ranges: &[AckRange],
        nranges: u8,
        now: Instant,
        out: &mut Vec<Vec<u8>>,
    ) {
        if self.state == State::Dead {
            return;
        }
        let ranges = &ranges[..(nranges as usize).min(ranges.len())];
        self.peer_ack = self.peer_ack.max(ack_to);

        let mut sample: Option<Duration> = None;
        let mut freed = 0usize;
        let mut kept = VecDeque::with_capacity(self.queue.len());
        for c in std::mem::take(&mut self.queue) {
            let acked = c.end() <= self.peer_ack
                || ranges
                    .iter()
                    .any(|r| r.start <= c.off && c.end() <= r.start + r.len as u64);
            if acked {
                freed += c.data.len();
                if c.retries == 0 {
                    let rtt = now.saturating_duration_since(c.sent_at);
                    sample = Some(sample.map_or(rtt, |s: Duration| s.max(rtt)));
                }
            } else {
                kept.push_back(c);
            }
        }
        self.queue = kept;
        self.inflight = self.inflight.saturating_sub(freed);
        if let Some(rtt) = sample {
            self.update_rtt(rtt);
        }

        let highest_acked = ranges
            .iter()
            .map(|r| r.start + r.len as u64)
            .chain(std::iter::once(self.peer_ack))
            .max()
            .unwrap_or(0);
        let patience = self.srtt.unwrap_or(MIN_RTO) / 8;
        let mut resend = Vec::new();
        for c in self.queue.iter_mut() {
            if c.end() <= highest_acked && now.saturating_duration_since(c.sent_at) >= patience {
                c.sent_at = now;
                c.retries += 1;
                resend.push((c.off, c.data.clone(), c.retries));
            }
        }
        for (off, data, retries) in resend {
            if retries > MAX_RETRIES {
                self.state = State::Dead;
                return;
            }
            out.push(encode_data(self.sid, off, &data));
        }
    }

    pub fn tick(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) {
        if self.state == State::Dead {
            return;
        }
        let rto = self.rto;
        let mut fired = false;
        let mut resend = Vec::new();
        for c in self.queue.iter_mut() {
            if now.saturating_duration_since(c.sent_at) >= rto {
                c.sent_at = now;
                c.retries += 1;
                if c.retries > MAX_RETRIES {
                    self.state = State::Dead;
                    return;
                }
                fired = true;
                resend.push((c.off, c.data.clone()));
                break;
            }
        }
        for (off, data) in resend {
            out.push(encode_data(self.sid, off, &data));
        }
        if fired {
            self.rto = (self.rto * 2).min(MAX_RTO);
        }
    }

    pub fn on_data(&mut self, off: u64, payload: &[u8], out: &mut Vec<Vec<u8>>) -> Vec<u8> {
        if self.state == State::Dead || payload.is_empty() {
            self.push_ack(out);
            return Vec::new();
        }
        let end = off + payload.len() as u64;
        if end <= self.read_off {
            self.push_ack(out);
            return Vec::new();
        }
        let (off, payload) = if off < self.read_off {
            let skip = (self.read_off - off) as usize;
            (self.read_off, &payload[skip..])
        } else {
            (off, payload)
        };

        if off == self.read_off {
            let mut delivered = payload.to_vec();
            self.read_off = off + payload.len() as u64;
            while let Some(next) = self.holes.remove(&self.read_off) {
                self.held -= next.len();
                self.read_off += next.len() as u64;
                delivered.extend_from_slice(&next);
            }
            self.check_peer_fin();
            self.push_ack(out);
            return delivered;
        }

        if self.held + payload.len() <= MAX_REASSEMBLY {
            if let Some(prev) = self.holes.insert(off, payload.to_vec()) {
                self.held -= prev.len();
            }
            self.held += payload.len();
        }
        self.push_ack(out);
        Vec::new()
    }

    pub fn on_fin(&mut self, final_off: u64, out: &mut Vec<Vec<u8>>) {
        self.peer_fin_at = Some(final_off);
        self.check_peer_fin();
        self.push_ack(out);
    }

    pub fn on_reset(&mut self) {
        self.state = State::Dead;
        self.queue.clear();
        self.holes.clear();
        self.inflight = 0;
        self.held = 0;
    }

    fn check_peer_fin(&mut self) {
        if self.state == State::Open && self.peer_fin_at == Some(self.read_off) {
            self.state = State::PeerFinished;
        }
    }

    pub fn ack_frame(&self) -> Vec<u8> {
        let mut ranges = [AckRange { start: 0, len: 0 }; SACK_RANGES];
        let mut n = 0;
        for (&start, data) in self.holes.iter() {
            if n == SACK_RANGES {
                break;
            }
            if n > 0 {
                let prev = &mut ranges[n - 1];
                if prev.start + prev.len as u64 == start {
                    prev.len += data.len() as u32;
                    continue;
                }
            }
            ranges[n] = AckRange {
                start,
                len: data.len() as u32,
            };
            n += 1;
        }
        let mut f = Vec::with_capacity(14 + n * 12);
        Frame::SAck {
            sid: self.sid,
            ack_to: self.read_off,
            ranges,
            nranges: n as u8,
        }
        .write(&mut f);
        f
    }

    fn push_ack(&self, out: &mut Vec<Vec<u8>>) {
        out.push(self.ack_frame());
    }

    fn update_rtt(&mut self, rtt: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let diff = rtt.abs_diff(srtt);
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((srtt * 7 + rtt) / 8);
            }
        }
        let srtt = self.srtt.unwrap_or(rtt);
        self.rto = (srtt + self.rttvar * 4).clamp(MIN_RTO, MAX_RTO);
    }
}

fn encode_data(sid: u32, off: u64, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(crate::wire::SDATA_HDR + payload.len());
    Frame::SData { sid, off, payload }.write(&mut f);
    f
}
