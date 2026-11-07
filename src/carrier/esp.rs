use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

use super::rawfd;
use super::rawip::{RawIp, Shape};

pub const HDR: usize = 8;

pub type Esp = RawIp<EspShape>;

pub fn spis(token: &[u8]) -> (u32, u32) {
    let k = blake3::derive_key("shabdiz-esp-spis-v1", token);
    let a = u32::from_be_bytes([k[0], k[1], k[2], k[3]]) | 0x1000_0000;
    let mut b = u32::from_be_bytes([k[4], k[5], k[6], k[7]]) | 0x1000_0000;
    if b == a {
        b = a.wrapping_add(1);
    }
    (a, b)
}

pub struct EspShape {
    local_spi: u32,
    peer_spi: u32,
    seq: AtomicU32,
}

impl Shape for EspShape {
    fn hdr(&self) -> usize {
        HDR
    }

    fn build(&self, datagram: &[u8], out: &mut [u8]) -> usize {
        frame(self.peer_spi, self.seq.fetch_add(1, Relaxed), datagram, out)
    }

    fn parse<'a>(&self, pkt: &'a [u8]) -> Option<&'a [u8]> {
        payload(pkt, self.local_spi)
    }
}

pub fn open(peer: Ipv4Addr, local_spi: u32, peer_spi: u32, mtu: usize) -> io::Result<Esp> {
    RawIp::open(
        libc::IPPROTO_ESP,
        "esp",
        peer,
        EspShape {
            local_spi,
            peer_spi,
            seq: AtomicU32::new(1),
        },
        mtu,
    )
}

pub fn frame(peer_spi: u32, seq: u32, datagram: &[u8], out: &mut [u8]) -> usize {
    out[..4].copy_from_slice(&peer_spi.to_be_bytes());
    out[4..8].copy_from_slice(&seq.to_be_bytes());
    out[HDR..HDR + datagram.len()].copy_from_slice(datagram);
    HDR + datagram.len()
}

pub fn payload(pkt: &[u8], local_spi: u32) -> Option<&[u8]> {
    let ihl = usize::from(*pkt.first()? & 0x0f) * 4;
    let b = pkt.get(ihl.max(20)..)?;
    if b.len() <= HDR {
        return None;
    }
    if b[..4] != local_spi.to_be_bytes() {
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
