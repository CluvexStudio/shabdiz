use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use super::{Batch, Carrier, BATCH};

const LEN: usize = 2;

pub const MAX_DATAGRAM: usize = 1400;

pub struct Tcp {
    read: Mutex<OwnedReadHalf>,
    write: Mutex<OwnedWriteHalf>,
    peer: SocketAddr,
}

impl Tcp {
    pub async fn connect(peer: SocketAddr) -> io::Result<Tcp> {
        let s = TcpStream::connect(peer).await?;
        Tcp::from_stream(s)
    }

    pub async fn accept(l: &TcpListener) -> io::Result<Tcp> {
        let (s, _) = l.accept().await?;
        Tcp::from_stream(s)
    }

    pub fn from_stream(s: TcpStream) -> io::Result<Tcp> {
        s.set_nodelay(true)?;
        let peer = s.peer_addr()?;
        let (r, w) = s.into_split();
        Ok(Tcp {
            read: Mutex::new(r),
            write: Mutex::new(w),
            peer,
        })
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
}

#[async_trait]
impl Carrier for Tcp {
    async fn send(&self, datagram: &[u8]) -> io::Result<()> {
        if datagram.len() > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram larger than this carrier's limit",
            ));
        }
        let mut w = self.write.lock().await;
        w.write_all(&(datagram.len() as u16).to_be_bytes()).await?;
        w.write_all(datagram).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut r = self.read.lock().await;
        loop {
            let mut len = [0u8; LEN];
            r.read_exact(&mut len).await?;
            let n = u16::from_be_bytes(len) as usize;
            if n == 0 {
                continue;
            }
            if n > buf.len() {
                let mut sink = vec![0u8; n];
                r.read_exact(&mut sink).await?;
                continue;
            }
            r.read_exact(&mut buf[..n]).await?;
            return Ok(n);
        }
    }

    fn mtu(&self) -> usize {
        MAX_DATAGRAM
    }

    fn batch_size(&self) -> usize {
        BATCH
    }

    async fn send_batch(&self, batch: &Batch) -> io::Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }
        let mut out = Vec::with_capacity(batch.len() * (LEN + batch.stride()));
        let mut n = 0;
        for d in batch.iter() {
            if d.len() > MAX_DATAGRAM {
                continue;
            }
            out.extend_from_slice(&(d.len() as u16).to_be_bytes());
            out.extend_from_slice(d);
            n += 1;
        }
        self.write.lock().await.write_all(&out).await?;
        Ok(n)
    }

    async fn recv_batch(&self, batch: &mut Batch) -> io::Result<usize> {
        batch.clear();
        let mut tmp = vec![0u8; batch.stride()];
        let n = self.recv(&mut tmp).await?;
        Ok(usize::from(batch.push(&tmp[..n])))
    }
}
