use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

use super::rawfd;
use super::rawip::{RawIp, Shape};

pub const HDR: usize = 8;

const NOT_IP: u32 = 0xB000_0000;
const NOT_IP_MASK: u32 = 0x0FFF_FFFF;

pub type Tagged = RawIp<TaggedShape>;

pub fn tags(token: &[u8], context: &'static str) -> (u32, u32) {
    let k = blake3::derive_key(context, token);
    let a = (u32::from_be_bytes([k[0], k[1], k[2], k[3]]) & NOT_IP_MASK) | NOT_IP;
    let mut b = (u32::from_be_bytes([k[4], k[5], k[6], k[7]]) & NOT_IP_MASK) | NOT_IP;
    if b == a {
        b = (a.wrapping_add(1) & NOT_IP_MASK) | NOT_IP;
    }
    (a, b)
}

pub struct TaggedShape {
    local: u32,
    peer: u32,
    seq: AtomicU32,
}

impl Shape for TaggedShape {
    fn hdr(&self) -> usize {
        HDR
    }

    fn build(&self, datagram: &[u8], out: &mut [u8]) -> usize {
        frame(self.peer, self.seq.fetch_add(1, Relaxed), datagram, out)
    }

    fn parse<'a>(&self, pkt: &'a [u8]) -> Option<&'a [u8]> {
        payload(pkt, self.local)
    }
}

pub fn open_ipip(peer: Ipv4Addr, local: u32, peer_tag: u32, mtu: usize) -> io::Result<Tagged> {
    open(libc::IPPROTO_IPIP, "ipip", peer, local, peer_tag, mtu)
}

pub fn open_sit(peer: Ipv4Addr, local: u32, peer_tag: u32, mtu: usize) -> io::Result<Tagged> {
    open(libc::IPPROTO_IPV6, "6to4", peer, local, peer_tag, mtu)
}

fn open(
    proto: libc::c_int,
    name: &str,
    peer: Ipv4Addr,
    local: u32,
    peer_tag: u32,
    mtu: usize,
) -> io::Result<Tagged> {
    RawIp::open(
        proto,
        name,
        peer,
        TaggedShape {
            local,
            peer: peer_tag,
            seq: AtomicU32::new(1),
        },
        mtu,
    )
}

pub fn frame(peer_tag: u32, seq: u32, datagram: &[u8], out: &mut [u8]) -> usize {
    out[..4].copy_from_slice(&peer_tag.to_be_bytes());
    out[4..8].copy_from_slice(&seq.to_be_bytes());
    out[HDR..HDR + datagram.len()].copy_from_slice(datagram);
    HDR + datagram.len()
}

pub fn payload(pkt: &[u8], local: u32) -> Option<&[u8]> {
    let ihl = usize::from(*pkt.first()? & 0x0f) * 4;
    let b = pkt.get(ihl.max(20)..)?;
    if b.len() <= HDR {
        return None;
    }
    if b[..4] != local.to_be_bytes() {
        return None;
    }
    Some(&b[HDR..])
}

pub fn path_mtu(path: usize) -> usize {
    path.saturating_sub(20 + HDR)
}

pub fn is_path_error(e: &io::Error) -> bool {
    rawfd::is_path_error(e)
}
