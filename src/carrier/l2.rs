use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;

use super::l2frame::{self, Frame, HEADERS, VNET_HDR};
use super::rawfd::{self, Side};
use super::{Batch, Carrier, Pacer, BATCH};

const RECV_BUF: libc::c_int = 8 * 1024 * 1024;

const PATH_MTU: usize = 1500;

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub offload: bool,
    pub suppress_rst: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            offload: true,
            suppress_rst: true,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Link {
    pub ifindex: i32,
    pub mtu: usize,
    pub src_mac: [u8; 6],
    pub gateway_mac: [u8; 6],
    pub src_ip: Ipv4Addr,
}

pub struct L2 {
    fd: AsyncFd<OwnedFd>,
    link: Link,
    peer: Ipv4Addr,
    sport: u16,
    dport: u16,
    vnet: bool,
    offload: bool,
    seq: AtomicU32,
    ip_id: AtomicU32,
    ts: AtomicU32,
    rst_rule: Option<String>,
    pacer: Pacer,
}

impl L2 {
    pub fn open(
        link: Link,
        peer: Ipv4Addr,
        sport: u16,
        dport: u16,
        opt: Options,
    ) -> io::Result<L2> {
        let eth_p_ip = (libc::ETH_P_IP as u16).to_be() as libc::c_int;
        let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_ip) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
        sll.sll_ifindex = link.ifindex;
        let r = unsafe {
            libc::bind(
                raw,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }

        attach_port_filter(raw, sport)?;
        let _ = rawfd::set_opt(raw, libc::SOL_SOCKET, libc::SO_RCVBUF, RECV_BUF);
        let vnet =
            opt.offload && rawfd::set_opt(raw, libc::SOL_PACKET, libc::PACKET_VNET_HDR, 1).is_ok();
        unsafe {
            let fl = libc::fcntl(raw, libc::F_GETFL);
            libc::fcntl(raw, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }

        let rst_rule = if opt.suppress_rst {
            suppress_rst(sport)
        } else {
            None
        };

        Ok(L2 {
            fd: unsafe { AsyncFd::register(owned)? },
            link,
            peer,
            sport,
            dport,
            vnet,
            offload: vnet,
            seq: AtomicU32::new(1),
            ip_id: AtomicU32::new(1),
            ts: AtomicU32::new(1),
            rst_rule,
            pacer: Pacer::default(),
        })
    }

    pub fn offload(&self) -> bool {
        self.offload
    }

    pub fn pacer(&self) -> &Pacer {
        &self.pacer
    }

    fn frame_for(&self, payload_len: usize) -> Frame {
        Frame {
            src_mac: self.link.src_mac,
            dst_mac: self.link.gateway_mac,
            src_ip: self.link.src_ip,
            dst_ip: self.peer,
            sport: self.sport,
            dport: self.dport,
            seq: self.seq.fetch_add(payload_len.max(1) as u32, Relaxed),
            ack: 0,
            tsval: self.ts.fetch_add(1, Relaxed),
            ip_id: self.ip_id.fetch_add(1, Relaxed) as u16,
        }
    }

    fn wire<'a>(&self, crafted: &'a [u8]) -> &'a [u8] {
        if self.vnet {
            crafted
        } else {
            &crafted[VNET_HDR..]
        }
    }

    async fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
        rawfd::retry(&self.fd, Side::Write, rawfd::never_tolerate, |fd| {
            rawfd::count(unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), 0) })
        })
        .await
        .map(|_| ())
    }

    pub fn kernel_drops(&self) -> u64 {
        #[repr(C)]
        #[derive(Default)]
        struct Stats {
            packets: libc::c_uint,
            drops: libc::c_uint,
        }
        let mut s = Stats::default();
        let mut len = std::mem::size_of::<Stats>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                self.fd.get_ref().as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                &mut s as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if r < 0 {
            0
        } else {
            s.drops as u64
        }
    }
}

#[async_trait]
impl Carrier for L2 {
    async fn send(&self, datagram: &[u8]) -> io::Result<()> {
        let mut out = Vec::with_capacity(VNET_HDR + HEADERS + datagram.len());
        l2frame::craft(&self.frame_for(datagram.len()), datagram, 0, &mut out);
        self.write_all(self.wire(&out)).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut frame = vec![0u8; VNET_HDR + self.link.mtu.max(PATH_MTU) + ETH_SLACK];
        loop {
            let n = self.read_once(&mut frame).await?;
            let Some(p) = l2frame::parse(&frame[..n], self.vnet, self.sport, self.dport) else {
                continue;
            };
            let take = if p.gso_size > 0 {
                p.gso_size.min(p.payload.len())
            } else {
                p.payload.len()
            };
            let m = take.min(buf.len());
            buf[..m].copy_from_slice(&p.payload[..m]);
            return Ok(m);
        }
    }

    fn mtu(&self) -> usize {
        l2frame::segment_mtu(self.link.mtu)
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
        let mut scratch = Vec::with_capacity(batch.len() * batch.stride());
        let mut out = Vec::with_capacity(VNET_HDR + HEADERS + batch.stride() * BATCH);
        let mut n = 0;
        if self.offload {
            for range in batch.groups(self.pacer.burst()) {
                self.pacer.admit(range.1 - range.0).await;
                let shaped = batch
                    .group_payload(range, &mut scratch)
                    .filter(|(seg, payload)| {
                        range.1 - range.0 >= 2
                            && *seg <= u16::MAX as usize
                            && payload.len() == seg * (range.1 - range.0)
                            && payload.len() > self.link.mtu
                    });
                match shaped {
                    Some((seg, payload)) if seg <= u16::MAX as usize => {
                        l2frame::craft(
                            &self.frame_for(payload.len()),
                            payload,
                            seg as u16,
                            &mut out,
                        );
                        self.write_all(self.wire(&out)).await?;
                        n += range.1 - range.0;
                    }
                    _ => {
                        for i in range.0..range.1 {
                            if let Some(d) = batch.get(i) {
                                self.send(d).await?;
                                n += 1;
                            }
                        }
                    }
                }
            }
            return Ok(n);
        }
        for d in batch.iter() {
            self.send(d).await?;
            n += 1;
        }
        Ok(n)
    }

    async fn recv_batch(&self, batch: &mut Batch) -> io::Result<usize> {
        batch.clear();
        let mut frame = vec![0u8; VNET_HDR + self.link.mtu.max(PATH_MTU) + ETH_SLACK];
        for _ in 0..SKIP_LIMIT {
            let n = self.read_once(&mut frame).await?;
            let Some(p) = l2frame::parse(&frame[..n], self.vnet, self.sport, self.dport) else {
                continue;
            };
            let got = if p.gso_size > 0 {
                batch.split_coalesced(p.payload, p.gso_size)
            } else {
                usize::from(batch.push(p.payload))
            };
            if got > 0 {
                return Ok(got);
            }
        }
        Ok(0)
    }
}

const ETH_SLACK: usize = 64;

const SKIP_LIMIT: usize = 1024;

impl L2 {
    async fn read_once(&self, buf: &mut [u8]) -> io::Result<usize> {
        rawfd::retry(&self.fd, Side::Read, rawfd::never_tolerate, |fd| {
            rawfd::count(unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) })
        })
        .await
    }
}

impl Drop for L2 {
    fn drop(&mut self) {
        if let Some(tag) = self.rst_rule.take() {
            let _ = std::process::Command::new("iptables")
                .args([
                    "-D",
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "--sport",
                    &self.sport.to_string(),
                ])
                .args([
                    "--tcp-flags",
                    "RST",
                    "RST",
                    "-m",
                    "comment",
                    "--comment",
                    &tag,
                    "-j",
                    "DROP",
                ])
                .status();
        }
    }
}

fn attach_port_filter(fd: RawFd, sport: u16) -> io::Result<()> {
    let mut prog = [
        libc::sock_filter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 12,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 6,
            k: 0x0800,
        },
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 23,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 4,
            k: 6,
        },
        libc::sock_filter {
            code: 0xb1,
            jt: 0,
            jf: 0,
            k: 14,
        },
        libc::sock_filter {
            code: 0x48,
            jt: 0,
            jf: 0,
            k: 16,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: sport as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0xffff,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn suppress_rst(sport: u16) -> Option<String> {
    let tag = format!("shabdiz-l2-{sport}");
    let ok = std::process::Command::new("iptables")
        .args(["-I", "OUTPUT", "-p", "tcp", "--sport", &sport.to_string()])
        .args([
            "--tcp-flags",
            "RST",
            "RST",
            "-m",
            "comment",
            "--comment",
            &tag,
            "-j",
            "DROP",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    ok.then_some(tag)
}

pub fn discover(peer: Ipv4Addr) -> io::Result<Link> {
    let src_ip = src_ip_for(peer)?;
    let (iface, gw) = default_route()?;
    let ifindex = unsafe {
        let name = std::ffi::CString::new(iface.clone()).map_err(io::Error::other)?;
        libc::if_nametoindex(name.as_ptr()) as i32
    };
    if ifindex == 0 {
        return Err(io::Error::other(format!("interface {iface} has no index")));
    }
    let src_mac = parse_mac(&std::fs::read_to_string(format!(
        "/sys/class/net/{iface}/address"
    ))?)
    .ok_or_else(|| io::Error::other("cannot parse the local MAC"))?;
    let mtu: usize = std::fs::read_to_string(format!("/sys/class/net/{iface}/mtu"))?
        .trim()
        .parse()
        .unwrap_or(1500);
    let gateway_mac = arp(gw)
        .or_else(|| {
            if let Ok(u) = std::net::UdpSocket::bind("0.0.0.0:0") {
                let _ = u.send_to(&[0u8; 1], std::net::SocketAddrV4::new(gw, 9));
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
            arp(gw)
        })
        .ok_or_else(|| io::Error::other("the gateway's MAC is not in the ARP table"))?;
    Ok(Link {
        ifindex,
        mtu,
        src_mac,
        gateway_mac,
        src_ip,
    })
}

fn src_ip_for(peer: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0")?;
    s.connect(std::net::SocketAddrV4::new(peer, 9))?;
    match s.local_addr()? {
        std::net::SocketAddr::V4(a) => Ok(*a.ip()),
        _ => Err(io::Error::other("no IPv4 source address for the peer")),
    }
}

fn default_route() -> io::Result<(String, Ipv4Addr)> {
    for line in std::fs::read_to_string("/proc/net/route")?.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 && f[1] == "00000000" {
            if let Ok(g) = u32::from_str_radix(f[2], 16) {
                return Ok((f[0].to_string(), Ipv4Addr::from(g.to_le_bytes())));
            }
        }
    }
    Err(io::Error::other("no default route"))
}

fn arp(ip: Ipv4Addr) -> Option<[u8; 6]> {
    let table = std::fs::read_to_string("/proc/net/arp").ok()?;
    let want = ip.to_string();
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 4 && f[0] == want {
            return parse_mac(f[3]);
        }
    }
    None
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut m = [0u8; 6];
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    for (i, p) in parts.iter().enumerate() {
        m[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(m)
}
