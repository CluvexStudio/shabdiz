use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use tokio::io::Interest;

use super::{Batch, Carrier, Pacer, BATCH};

const RECV_BUF: usize = 8 * 1024 * 1024;

pub struct Udp {
    sock: Arc<tokio::net::UdpSocket>,
    state: UdpSocketState,
    pacer: Pacer,
    peer: RwLock<Option<SocketAddr>>,
    gso: usize,
    mtu: usize,
}

impl Udp {
    pub async fn connect(local: SocketAddr, peer: SocketAddr) -> io::Result<Udp> {
        let u = Udp::bind(local).await?;
        *u.peer.write().expect("peer lock") = Some(peer);
        Ok(u)
    }

    pub async fn bind(local: SocketAddr) -> io::Result<Udp> {
        let sock = tokio::net::UdpSocket::bind(local).await?;
        let state = UdpSocketState::new(UdpSockRef::from(&sock))?;
        let _ = state.set_recv_buffer_size(UdpSockRef::from(&sock), RECV_BUF);
        let gso = state.max_gso_segments().max(1);
        let mtu = 1472;
        Ok(Udp {
            sock: Arc::new(sock),
            state,
            pacer: Pacer::new(gso.min(BATCH)),
            peer: RwLock::new(None),
            gso,
            mtu,
        })
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        *self.peer.read().expect("peer lock")
    }

    fn learn(&self, from: SocketAddr) {
        let mut p = self.peer.write().expect("peer lock");
        if p.is_none() {
            *p = Some(from);
        }
    }

    fn destination(&self) -> io::Result<SocketAddr> {
        self.peer().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "no peer yet: this end does not speak first",
            )
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    pub fn max_segments(&self) -> usize {
        self.gso
    }

    pub fn pacer(&self) -> &Pacer {
        &self.pacer
    }

    async fn try_send(&self, t: &Transmit<'_>) -> io::Result<()> {
        loop {
            self.sock.writable().await?;
            let r = self.sock.try_io(Interest::WRITABLE, || {
                self.state.try_send(UdpSockRef::from(&*self.sock), t)
            });
            match r {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

#[async_trait]
impl Carrier for Udp {
    async fn send(&self, datagram: &[u8]) -> io::Result<()> {
        self.try_send(&Transmit {
            destination: self.destination()?,
            ecn: None,
            contents: datagram,
            segment_size: None,
            src_ip: None,
        })
        .await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            self.sock.readable().await?;
            let mut meta = [RecvMeta::default()];
            let r = {
                let mut bufs = [io::IoSliceMut::new(buf)];
                self.sock.try_io(Interest::READABLE, || {
                    self.state
                        .recv(UdpSockRef::from(&*self.sock), &mut bufs, &mut meta)
                })
            };
            match r {
                Ok(0) => continue,
                Ok(_) => {
                    let m = &meta[0];
                    self.learn(m.addr);
                    let n = if m.stride > 0 {
                        m.stride.min(m.len)
                    } else {
                        m.len
                    };
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn batch_size(&self) -> usize {
        BATCH.min(self.gso)
    }

    fn pacer(&self) -> Option<&Pacer> {
        Some(&self.pacer)
    }

    async fn send_batch(&self, batch: &Batch) -> io::Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }
        let mut scratch = Vec::with_capacity(batch.len() * batch.stride());
        let burst = self.pacer.burst().min(self.gso.max(1));
        let mut n = 0;
        for range in batch.groups(burst) {
            self.pacer.admit(range.1 - range.0).await;
            let shaped = batch
                .group_payload(range, &mut scratch)
                .filter(|(seg, payload)| {
                    range.1 - range.0 > 1 && payload.len() == seg * (range.1 - range.0)
                });
            match shaped {
                Some((seg, payload)) => {
                    let destination = self.destination()?;
                    self.try_send(&Transmit {
                        destination,
                        ecn: None,
                        contents: payload,
                        segment_size: Some(seg),
                        src_ip: None,
                    })
                    .await?;
                    n += range.1 - range.0;
                }
                None => {
                    for i in range.0..range.1 {
                        if let Some(d) = batch.get(i) {
                            self.send(d).await?;
                            n += 1;
                        }
                    }
                }
            }
        }
        Ok(n)
    }

    async fn recv_batch(&self, batch: &mut Batch) -> io::Result<usize> {
        batch.clear();
        let stride = batch.stride();
        let mut store = vec![0u8; stride * BATCH];
        loop {
            self.sock.readable().await?;
            let mut metas = [RecvMeta::default(); BATCH];
            let r = {
                let mut bufs: Vec<io::IoSliceMut> =
                    store.chunks_mut(stride).map(io::IoSliceMut::new).collect();
                self.sock.try_io(Interest::READABLE, || {
                    self.state
                        .recv(UdpSockRef::from(&*self.sock), &mut bufs, &mut metas)
                })
            };
            match r {
                Ok(0) => continue,
                Ok(msgs) => {
                    let mut n = 0;
                    if let Some(m) = metas.first() {
                        self.learn(m.addr);
                    }
                    for (i, m) in metas.iter().take(msgs).enumerate() {
                        let at = i * stride;
                        let got = &store[at..at + m.len.min(stride)];
                        if m.stride > 0 && m.stride < got.len() {
                            for chunk in got.chunks(m.stride) {
                                if !batch.push(chunk) {
                                    break;
                                }
                                n += 1;
                            }
                        } else if batch.push(got) {
                            n += 1;
                        }
                    }
                    if n > 0 {
                        return Ok(n);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

pub fn offload_available() -> bool {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|s| UdpSocketState::new(UdpSockRef::from(&s)).ok())
        .map(|st| st.max_gso_segments() > 1)
        .unwrap_or(false)
}

pub fn wildcard_for(peer: SocketAddr) -> SocketAddr {
    match peer.ip() {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    }
}
