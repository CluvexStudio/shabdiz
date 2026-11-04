pub type Cid = [u8; 8];

pub const CID_HANDSHAKE: Cid = [0; 8];

pub const CID_LEN: usize = 8;
pub const CTR_LEN: usize = 8;
pub const HEAD: usize = CID_LEN + CTR_LEN;
pub const TAG: usize = 16;
pub const OVERHEAD: usize = HEAD + TAG;

pub const T_DATA: u8 = 0x01;
pub const T_PING: u8 = 0x02;
pub const T_PONG: u8 = 0x03;
pub const T_OPEN: u8 = 0x04;
pub const T_CLOSE: u8 = 0x05;
pub const T_TOOBIG: u8 = 0x06;
pub const T_STAT: u8 = 0x07;
pub const T_PAD: u8 = 0x08;
pub const T_PROBE: u8 = 0x09;
pub const T_PROBEACK: u8 = 0x0a;
pub const T_SOPEN: u8 = 0x10;
pub const T_SDATA: u8 = 0x11;
pub const T_SACK: u8 = 0x12;
pub const T_SFIN: u8 = 0x13;
pub const T_SRST: u8 = 0x14;

pub const HS_MSG1: u8 = 1;
pub const HS_MSG2: u8 = 2;

pub const DATA_HDR: usize = 3;
pub const SDATA_HDR: usize = 13;
pub const SACK_RANGES: usize = 4;
pub const PROBE_HDR: usize = 5;

pub fn probe_fill(payload: usize) -> usize {
    (payload + DATA_HDR).saturating_sub(PROBE_HDR)
}

pub fn payload_mtu(carrier_mtu: usize) -> usize {
    carrier_mtu.saturating_sub(OVERHEAD + DATA_HDR)
}

pub fn stream_mtu(carrier_mtu: usize) -> usize {
    carrier_mtu.saturating_sub(OVERHEAD + SDATA_HDR)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub cid: Cid,
    pub ctr: u64,
}

impl Head {
    pub fn parse(d: &[u8]) -> Option<Head> {
        if d.len() < OVERHEAD {
            return None;
        }
        let mut cid = [0u8; CID_LEN];
        cid.copy_from_slice(&d[..CID_LEN]);
        let ctr = u64::from_be_bytes(d[CID_LEN..HEAD].try_into().ok()?);
        Some(Head { cid, ctr })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.cid);
        out.extend_from_slice(&self.ctr.to_be_bytes());
    }
}

pub fn is_handshake(d: &[u8]) -> bool {
    d.len() > CID_LEN && d[..CID_LEN] == CID_HANDSHAKE
}

pub fn handshake_datagram(kind: u8, noise: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&CID_HANDSHAKE);
    out.push(kind);
    out.extend_from_slice(noise);
}

pub fn parse_handshake(d: &[u8]) -> Option<(u8, &[u8])> {
    if !is_handshake(d) || d.len() < CID_LEN + 1 {
        return None;
    }
    Some((d[CID_LEN], &d[CID_LEN + 1..]))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub recv: u64,
    pub lost: u64,
    pub jitter_us: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKind {
    Tcp,
}

impl StreamKind {
    pub fn code(self) -> u8 {
        match self {
            StreamKind::Tcp => 1,
        }
    }
    pub fn from_code(c: u8) -> Option<StreamKind> {
        match c {
            1 => Some(StreamKind::Tcp),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckRange {
    pub start: u64,
    pub len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    Data {
        flow: u16,
        payload: &'a [u8],
    },
    Ping {
        tx_ts: u64,
    },
    Pong {
        echo_ts: u64,
        rx_ts: u64,
    },
    Open {
        flow: u16,
        target: &'a str,
    },
    Close {
        flow: u16,
    },
    TooBig {
        mtu: u16,
    },
    Stat(Stat),
    Pad,
    Probe {
        seq: u16,
        payload: u16,
        fill: &'a [u8],
    },
    ProbeAck {
        seq: u16,
        payload: u16,
    },
    SOpen {
        sid: u32,
        kind: StreamKind,
        target: &'a str,
    },
    SData {
        sid: u32,
        off: u64,
        payload: &'a [u8],
    },
    SAck {
        sid: u32,
        ack_to: u64,
        ranges: [AckRange; SACK_RANGES],
        nranges: u8,
    },
    SFin {
        sid: u32,
        final_off: u64,
    },
    SRst {
        sid: u32,
        code: u8,
    },
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
fn be32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?))
}
fn be64(b: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(i..i + 8)?.try_into().ok()?))
}

impl Frame<'_> {
    pub fn write(&self, out: &mut Vec<u8>) {
        match *self {
            Frame::Data { flow, payload } => {
                out.push(T_DATA);
                out.extend_from_slice(&flow.to_be_bytes());
                out.extend_from_slice(payload);
            }
            Frame::Ping { tx_ts } => {
                out.push(T_PING);
                out.extend_from_slice(&tx_ts.to_be_bytes());
            }
            Frame::Pong { echo_ts, rx_ts } => {
                out.push(T_PONG);
                out.extend_from_slice(&echo_ts.to_be_bytes());
                out.extend_from_slice(&rx_ts.to_be_bytes());
            }
            Frame::Open { flow, target } => {
                out.push(T_OPEN);
                out.extend_from_slice(&flow.to_be_bytes());
                out.extend_from_slice(target.as_bytes());
            }
            Frame::Close { flow } => {
                out.push(T_CLOSE);
                out.extend_from_slice(&flow.to_be_bytes());
            }
            Frame::TooBig { mtu } => {
                out.push(T_TOOBIG);
                out.extend_from_slice(&mtu.to_be_bytes());
            }
            Frame::Stat(s) => {
                out.push(T_STAT);
                out.extend_from_slice(&s.recv.to_be_bytes());
                out.extend_from_slice(&s.lost.to_be_bytes());
                out.extend_from_slice(&s.jitter_us.to_be_bytes());
            }
            Frame::Pad => out.push(T_PAD),
            Frame::Probe { seq, payload, fill } => {
                out.push(T_PROBE);
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(&payload.to_be_bytes());
                out.extend_from_slice(fill);
            }
            Frame::ProbeAck { seq, payload } => {
                out.push(T_PROBEACK);
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(&payload.to_be_bytes());
            }
            Frame::SOpen { sid, kind, target } => {
                out.push(T_SOPEN);
                out.extend_from_slice(&sid.to_be_bytes());
                out.push(kind.code());
                out.extend_from_slice(target.as_bytes());
            }
            Frame::SData { sid, off, payload } => {
                out.push(T_SDATA);
                out.extend_from_slice(&sid.to_be_bytes());
                out.extend_from_slice(&off.to_be_bytes());
                out.extend_from_slice(payload);
            }
            Frame::SAck {
                sid,
                ack_to,
                ranges,
                nranges,
            } => {
                out.push(T_SACK);
                out.extend_from_slice(&sid.to_be_bytes());
                out.extend_from_slice(&ack_to.to_be_bytes());
                let n = (nranges as usize).min(SACK_RANGES);
                out.push(n as u8);
                for r in &ranges[..n] {
                    out.extend_from_slice(&r.start.to_be_bytes());
                    out.extend_from_slice(&r.len.to_be_bytes());
                }
            }
            Frame::SFin { sid, final_off } => {
                out.push(T_SFIN);
                out.extend_from_slice(&sid.to_be_bytes());
                out.extend_from_slice(&final_off.to_be_bytes());
            }
            Frame::SRst { sid, code } => {
                out.push(T_SRST);
                out.extend_from_slice(&sid.to_be_bytes());
                out.push(code);
            }
        }
    }

    pub fn parse(d: &[u8]) -> Option<Frame<'_>> {
        let (&t, b) = d.split_first()?;
        match t {
            T_DATA => Some(Frame::Data {
                flow: be16(b, 0)?,
                payload: b.get(2..)?,
            }),
            T_PING => Some(Frame::Ping { tx_ts: be64(b, 0)? }),
            T_PONG => Some(Frame::Pong {
                echo_ts: be64(b, 0)?,
                rx_ts: be64(b, 8)?,
            }),
            T_OPEN => Some(Frame::Open {
                flow: be16(b, 0)?,
                target: std::str::from_utf8(b.get(2..)?).ok()?,
            }),
            T_CLOSE => Some(Frame::Close { flow: be16(b, 0)? }),
            T_TOOBIG => Some(Frame::TooBig { mtu: be16(b, 0)? }),
            T_STAT => Some(Frame::Stat(Stat {
                recv: be64(b, 0)?,
                lost: be64(b, 8)?,
                jitter_us: be32(b, 16)?,
            })),
            T_PAD => Some(Frame::Pad),
            T_PROBE => Some(Frame::Probe {
                seq: be16(b, 0)?,
                payload: be16(b, 2)?,
                fill: b.get(4..)?,
            }),
            T_PROBEACK => Some(Frame::ProbeAck {
                seq: be16(b, 0)?,
                payload: be16(b, 2)?,
            }),
            T_SOPEN => Some(Frame::SOpen {
                sid: be32(b, 0)?,
                kind: StreamKind::from_code(*b.get(4)?)?,
                target: std::str::from_utf8(b.get(5..)?).ok()?,
            }),
            T_SDATA => Some(Frame::SData {
                sid: be32(b, 0)?,
                off: be64(b, 4)?,
                payload: b.get(12..)?,
            }),
            T_SACK => {
                let (sid, ack_to) = (be32(b, 0)?, be64(b, 4)?);
                let n = *b.get(12)? as usize;
                if n > SACK_RANGES {
                    return None;
                }
                let mut ranges = [AckRange { start: 0, len: 0 }; SACK_RANGES];
                for (i, r) in ranges.iter_mut().enumerate().take(n) {
                    let at = 13 + i * 12;
                    *r = AckRange {
                        start: be64(b, at)?,
                        len: be32(b, at + 8)?,
                    };
                }
                Some(Frame::SAck {
                    sid,
                    ack_to,
                    ranges,
                    nranges: n as u8,
                })
            }
            T_SFIN => Some(Frame::SFin {
                sid: be32(b, 0)?,
                final_off: be64(b, 4)?,
            }),
            T_SRST => Some(Frame::SRst {
                sid: be32(b, 0)?,
                code: *b.get(4)?,
            }),
            _ => None,
        }
    }
}
