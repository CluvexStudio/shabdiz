use std::net::Ipv4Addr;

pub const VNET_HDR: usize = 10;
pub const ETH_HDR: usize = 14;
pub const IP4_HDR: usize = 20;
pub const TCP_HDR: usize = 20;
pub const TCP_OPTS: usize = 20;
pub const HEADERS: usize = ETH_HDR + IP4_HDR + TCP_HDR + TCP_OPTS;

const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;

#[derive(Clone, Copy, Debug)]
pub struct Frame {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub tsval: u32,
    pub ip_id: u16,
}

pub fn checksum(data: &[u8], init: u32) -> u16 {
    let mut sum = init;
    let chunks = data.as_chunks::<2>();
    for c in chunks.0 {
        sum += u16::from_be_bytes(*c) as u32;
    }
    if let [last] = *chunks.1 {
        sum += (last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn pseudo_sum(src: Ipv4Addr, dst: Ipv4Addr, seg_len: u16) -> u32 {
    let (s, d) = (src.octets(), dst.octets());
    u16::from_be_bytes([s[0], s[1]]) as u32
        + u16::from_be_bytes([s[2], s[3]]) as u32
        + u16::from_be_bytes([d[0], d[1]]) as u32
        + u16::from_be_bytes([d[2], d[3]]) as u32
        + 6
        + seg_len as u32
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn vnet(out: &mut Vec<u8>, gso_size: u16) {
    if gso_size == 0 {
        out.extend_from_slice(&[0u8; VNET_HDR]);
        return;
    }
    out.push(VIRTIO_NET_HDR_F_NEEDS_CSUM);
    out.push(VIRTIO_NET_HDR_GSO_TCPV4);
    out.extend_from_slice(&(HEADERS as u16).to_le_bytes());
    out.extend_from_slice(&gso_size.to_le_bytes());
    out.extend_from_slice(&((ETH_HDR + IP4_HDR) as u16).to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    debug_assert_eq!(out.len(), VNET_HDR);
}

pub fn craft(f: &Frame, payload: &[u8], gso_size: u16, out: &mut Vec<u8>) {
    out.clear();
    out.reserve(VNET_HDR + HEADERS + payload.len());
    vnet(out, gso_size);
    let frame = out.len();

    out.extend_from_slice(&f.dst_mac);
    out.extend_from_slice(&f.src_mac);
    out.extend_from_slice(&[0x08, 0x00]);

    let total = (IP4_HDR + TCP_HDR + TCP_OPTS + payload.len()) as u16;
    out.extend_from_slice(&[0x45, 0x00]);
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&f.ip_id.to_be_bytes());
    out.extend_from_slice(&0x4000u16.to_be_bytes());
    out.push(64);
    out.push(6);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&f.src_ip.octets());
    out.extend_from_slice(&f.dst_ip.octets());

    out.extend_from_slice(&f.sport.to_be_bytes());
    out.extend_from_slice(&f.dport.to_be_bytes());
    out.extend_from_slice(&f.seq.to_be_bytes());
    out.extend_from_slice(&f.ack.to_be_bytes());
    out.push((((TCP_HDR + TCP_OPTS) / 4) << 4) as u8);
    out.push(0b0001_1000);
    out.extend_from_slice(&65535u16.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&[2, 4, 0x05, 0xb4]);
    out.push(1);
    out.extend_from_slice(&[3, 3, 7]);
    out.push(1);
    out.push(1);
    out.extend_from_slice(&[8, 10]);
    out.extend_from_slice(&f.tsval.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(payload);

    let ip = frame + ETH_HDR;
    let tcp = ip + IP4_HDR;
    let ic = checksum(&out[ip..tcp], 0);
    out[ip + 10..ip + 12].copy_from_slice(&ic.to_be_bytes());

    let sum = if gso_size == 0 {
        let seg_len = (out.len() - tcp) as u16;
        checksum(&out[tcp..], pseudo_sum(f.src_ip, f.dst_ip, seg_len))
    } else {
        fold(pseudo_sum(f.src_ip, f.dst_ip, 0))
    };
    out[tcp + 16..tcp + 18].copy_from_slice(&sum.to_be_bytes());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parsed<'a> {
    pub src_ip: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
    pub gso_size: usize,
}

pub fn parse(d: &[u8], vnet_on: bool, sport: u16, dport: u16) -> Option<Parsed<'_>> {
    let d = if vnet_on {
        if d.len() < VNET_HDR {
            return None;
        }
        let gso = u16::from_le_bytes([d[4], d[5]]) as usize;
        let rest = &d[VNET_HDR..];
        let mut p = parse_frame(rest, sport, dport)?;
        if d[1] != VIRTIO_NET_HDR_GSO_NONE && gso > 0 {
            p.gso_size = gso;
        }
        return Some(p);
    } else {
        d
    };
    parse_frame(d, sport, dport)
}

fn parse_frame(d: &[u8], sport: u16, dport: u16) -> Option<Parsed<'_>> {
    if d.len() < ETH_HDR + IP4_HDR + TCP_HDR || d[12] != 0x08 || d[13] != 0x00 {
        return None;
    }
    let ip = &d[ETH_HDR..];
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < IP4_HDR || ip.len() < ihl + TCP_HDR || ip[9] != 6 {
        return None;
    }
    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let tcp = &ip[ihl..];
    let (sp, dp) = (
        u16::from_be_bytes([tcp[0], tcp[1]]),
        u16::from_be_bytes([tcp[2], tcp[3]]),
    );
    if sp != dport || dp != sport {
        return None;
    }
    let doff = ((tcp[12] >> 4) as usize) * 4;
    if doff < TCP_HDR || tcp.len() <= doff {
        return None;
    }
    Some(Parsed {
        src_ip,
        sport: sp,
        dport: dp,
        payload: &tcp[doff..],
        gso_size: 0,
    })
}

pub fn segment_mtu(if_mtu: usize) -> usize {
    if_mtu.saturating_sub(IP4_HDR + TCP_HDR + TCP_OPTS)
}
