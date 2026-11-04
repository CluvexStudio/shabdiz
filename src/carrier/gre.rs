use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;

use super::rawfd::{self, Side};
use super::{Batch, Carrier, Pacer, BATCH};

const GRE_HDR: [u8; 4] = [0x00, 0x00, 0x65, 0x58];

const ETHERTYPE: [u8; 2] = [0x88, 0xb5];

pub const HDR: usize = GRE_HDR.len() + 14;

const MAX_FRAME: usize = 2048;

const RECV_BUF: libc::c_int = 8 * 1024 * 1024;

const SKIP_LIMIT: usize = 1024;

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

pub struct Gre {
    fd: AsyncFd<OwnedFd>,
    local_mac: [u8; 6],
    peer_mac: [u8; 6],
    mtu: usize,
    pacer: Pacer,
    foreign: AtomicU64,
    icmp: AtomicU64,
}

impl Gre {
    pub fn open(
        peer: Ipv4Addr,
        local_mac: [u8; 6],
        peer_mac: [u8; 6],
        mtu: usize,
    ) -> io::Result<Gre> {
        if mtu + HDR > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "gre mtu {mtu} exceeds the {} this carrier frames",
                    MAX_FRAME - HDR
                ),
            ));
        }
        let raw = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                libc::IPPROTO_GRE,
            )
        };
        if raw < 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(
                e.kind(),
                format!("opening a raw GRE socket ({e}) — this carrier needs CAP_NET_RAW"),
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        rawfd::set_opt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, RECV_BUF)?;
        let _ = rawfd::set_opt(
            fd.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_DO,
        );
        let sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(peer.octets()),
            },
            sin_zero: [0; 8],
        };
        let r = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Gre {
            fd: unsafe { AsyncFd::register(fd)? },
            local_mac,
            peer_mac,
            mtu,
            pacer: Pacer::new(BATCH),
            foreign: AtomicU64::new(0),
            icmp: AtomicU64::new(0),
        })
    }

    pub fn pacer(&self) -> &Pacer {
        &self.pacer
    }

    pub fn foreign(&self) -> u64 {
        self.foreign.load(Relaxed)
    }

    pub fn icmp_errors(&self) -> u64 {
        self.icmp.load(Relaxed)
    }

    fn build(&self, datagram: &[u8], out: &mut [u8]) -> usize {
        frame(self.peer_mac, self.local_mac, datagram, out)
    }

    fn parse<'a>(&self, pkt: &'a [u8]) -> Option<&'a [u8]> {
        payload(pkt, self.local_mac)
    }

    fn survive_icmp(&self) -> impl Fn(&io::Error) -> bool + '_ {
        move |e| {
            let path = is_path_error(e);
            if path {
                self.icmp.fetch_add(1, Relaxed);
            }
            path
        }
    }

    async fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
        rawfd::retry(&self.fd, Side::Write, self.survive_icmp(), |fd| {
            rawfd::count(unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), 0) })
        })
        .await
        .map(|_| ())
    }

    async fn read_once(&self, buf: &mut [u8]) -> io::Result<usize> {
        let (fd, tolerate) = (&self.fd, self.survive_icmp());
        rawfd::retry(fd, Side::Read, tolerate, |fd| {
            rawfd::count(unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) })
        })
        .await
    }

    async fn send_group(&self, scratch: &[u8], lens: &[usize]) -> io::Result<usize> {
        rawfd::retry(&self.fd, Side::Write, self.survive_icmp(), |fd| {
            let mut iov: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
            let mut msgs: [libc::mmsghdr; BATCH] = unsafe { std::mem::zeroed() };
            let mut at = 0;
            for (i, &len) in lens.iter().enumerate() {
                iov[i] = libc::iovec {
                    iov_base: scratch[at..].as_ptr() as *mut libc::c_void,
                    iov_len: len,
                };
                msgs[i].msg_hdr.msg_iov = &mut iov[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                at += len;
            }
            rawfd::count(unsafe {
                libc::sendmmsg(fd, msgs.as_mut_ptr(), lens.len() as u32, 0) as isize
            })
        })
        .await
    }
}

#[async_trait]
impl Carrier for Gre {
    async fn send(&self, datagram: &[u8]) -> io::Result<()> {
        if datagram.len() > self.mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram exceeds the carrier mtu",
            ));
        }
        let mut frame = [0u8; MAX_FRAME];
        let n = self.build(datagram, &mut frame);
        self.write_all(&frame[..n]).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut pkt = [0u8; MAX_FRAME + 64];
        loop {
            let n = self.read_once(&mut pkt).await?;
            match self.parse(&pkt[..n]) {
                Some(p) => {
                    let m = p.len().min(buf.len());
                    buf[..m].copy_from_slice(&p[..m]);
                    return Ok(m);
                }
                None => {
                    self.foreign.fetch_add(1, Relaxed);
                }
            }
        }
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn batch_size(&self) -> usize {
        BATCH
    }

    fn pacer(&self) -> Option<&Pacer> {
        Some(&self.pacer)
    }

    async fn send_batch(&self, batch: &Batch) -> io::Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }
        let stride = HDR + batch.stride();
        let mut scratch = vec![0u8; stride * batch.len().min(BATCH)];
        let mut lens: Vec<usize> = Vec::with_capacity(BATCH);
        let mut sent = 0;
        for range in batch.groups(self.pacer.burst()) {
            self.pacer.admit(range.1 - range.0).await;
            lens.clear();
            let mut at = 0;
            for i in range.0..range.1 {
                let Some(d) = batch.get(i) else { continue };
                let n = self.build(d, &mut scratch[at..at + stride]);
                lens.push(n);
                at += n;
            }
            if lens.is_empty() {
                continue;
            }
            sent += self.send_group(&scratch[..at], &lens).await?;
        }
        Ok(sent)
    }

    async fn recv_batch(&self, batch: &mut Batch) -> io::Result<usize> {
        batch.clear();
        let stride = HDR + self.mtu + 64;
        let mut scratch = vec![0u8; stride * BATCH];
        for _ in 0..SKIP_LIMIT {
            let got = self.recv_group(&mut scratch, stride).await?;
            let mut n = 0;
            for (i, len) in got.iter().enumerate() {
                let pkt = &scratch[i * stride..i * stride + len];
                let Some(p) = self.parse(pkt) else {
                    self.foreign.fetch_add(1, Relaxed);
                    continue;
                };
                if batch.is_full() {
                    break;
                }
                if !batch.push(p) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "this batch holds {} bytes per datagram but the carrier delivered {}; \
                             size the batch from Carrier::mtu()",
                            batch.stride(),
                            p.len()
                        ),
                    ));
                }
                n += 1;
            }
            if n > 0 {
                return Ok(n);
            }
        }
        Ok(0)
    }
}

impl Gre {
    async fn recv_group(&self, scratch: &mut [u8], stride: usize) -> io::Result<Vec<usize>> {
        let (fd, tolerate) = (&self.fd, self.survive_icmp());
        rawfd::retry(fd, Side::Read, tolerate, |fd| {
            let base = scratch.as_mut_ptr();
            let mut iov: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
            let mut msgs: [libc::mmsghdr; BATCH] = unsafe { std::mem::zeroed() };
            for i in 0..BATCH {
                iov[i] = libc::iovec {
                    iov_base: unsafe { base.add(i * stride) }.cast(),
                    iov_len: stride,
                };
                msgs[i].msg_hdr.msg_iov = &mut iov[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
            }
            let got = rawfd::count(unsafe {
                libc::recvmmsg(fd, msgs.as_mut_ptr(), BATCH as u32, 0, std::ptr::null_mut())
                    as isize
            })?;
            Ok((0..got)
                .map(|i| msgs[i].msg_len as usize)
                .collect::<Vec<_>>())
        })
        .await
    }
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
    matches!(
        e.raw_os_error(),
        Some(libc::ENOPROTOOPT)
            | Some(libc::EHOSTUNREACH)
            | Some(libc::ENETUNREACH)
            | Some(libc::ECONNREFUSED)
            | Some(libc::ETIMEDOUT)
            | Some(libc::ENETDOWN)
            | Some(libc::EPROTO)
    )
}
