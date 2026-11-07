use std::io;
use std::net::Ipv4Addr;

use super::rawfd;
use super::rawip::{RawIp, Shape};

const GRE_HDR: [u8; 4] = [0x00, 0x00, 0x65, 0x58];

const ETHERTYPE: [u8; 2] = [0x88, 0xb5];

pub const HDR: usize = GRE_HDR.len() + 14;

pub type Gre = RawIp<GreShape>;

pub fn macs(token: &[u8]) -> ([u8; 6], [u8; 6]) {
    let k = blake3::derive_key("shabdiz-gre-macs-v1", token);
    let mut entry = [0u8; 6];
    let mut exit = [0u8; 6];
    entry.copy_from_slice(&k[..6]);
    exit.copy_from_slice(&k[6..12]);
    entry[0] = (entry[0] & 0xfe) | 0x02;
    exit[0] = (exit[0] & 0xfe) | 0x02;
    (entry, exit)
}

pub struct GreShape {
    local_mac: [u8; 6],
    peer_mac: [u8; 6],
}

impl Shape for GreShape {
    fn hdr(&self) -> usize {
        HDR
    }

    fn build(&self, datagram: &[u8], out: &mut [u8]) -> usize {
        frame(self.peer_mac, self.local_mac, datagram, out)
    }

    fn parse<'a>(&self, pkt: &'a [u8]) -> Option<&'a [u8]> {
        payload(pkt, self.local_mac)
    }
}

pub fn open(peer: Ipv4Addr, local_mac: [u8; 6], peer_mac: [u8; 6], mtu: usize) -> io::Result<Gre> {
    RawIp::open(
        libc::IPPROTO_GRE,
        "gre",
        peer,
        GreShape {
            local_mac,
            peer_mac,
        },
        mtu,
    )
}

pub fn frame(dst_mac: [u8; 6], src_mac: [u8; 6], datagram: &[u8], out: &mut [u8]) -> usize {
    out[..4].copy_from_slice(&GRE_HDR);
    out[4..10].copy_from_slice(&dst_mac);
    out[10..16].copy_from_slice(&src_mac);
    out[16..18].copy_from_slice(&ETHERTYPE);
    out[HDR..HDR + datagram.len()].copy_from_slice(datagram);
    HDR + datagram.len()
}

pub fn payload(pkt: &[u8], local_mac: [u8; 6]) -> Option<&[u8]> {
    let ihl = usize::from(*pkt.first()? & 0x0f) * 4;
    let b = pkt.get(ihl.max(20)..)?;
    if b.len() <= HDR || b[..4] != GRE_HDR {
        return None;
    }
    if b[4..10] != local_mac || b[16..18] != ETHERTYPE {
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
