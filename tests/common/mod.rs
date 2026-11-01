use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;

use async_trait::async_trait;
use shabdiz::carrier::Pacer;
use shabdiz::Carrier;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;

pub struct Pipe {
    pacer: Pacer,
    out: UnboundedSender<Vec<u8>>,
    inbox: Mutex<UnboundedReceiver<Vec<u8>>>,
    mtu: usize,
    sends: AtomicUsize,
    drop_sends: Vec<usize>,
    pub delivered: AtomicUsize,
    cut: AtomicBool,
}

#[async_trait]
impl Carrier for Pipe {
    async fn send(&self, datagram: &[u8]) -> std::io::Result<()> {
        let n = self.sends.fetch_add(1, SeqCst) + 1;
        if self.cut.load(SeqCst) {
            return Ok(());
        }
        if self.drop_sends.contains(&n) {
            return Ok(());
        }
        self.delivered.fetch_add(1, SeqCst);
        let _ = self.out.send(datagram.to_vec());
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cut.load(SeqCst) {
            return std::future::pending().await;
        }
        let mut inbox = self.inbox.lock().await;
        match inbox.recv().await {
            Some(d) => {
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                Ok(n)
            }
            None => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
        }
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn pacer(&self) -> Option<&Pacer> {
        Some(&self.pacer)
    }
}

#[allow(dead_code)]
impl Pipe {
    pub fn sends(&self) -> usize {
        self.sends.load(SeqCst)
    }

    pub fn pacer(&self) -> &Pacer {
        &self.pacer
    }

    pub fn cut(&self) {
        self.cut.store(true, SeqCst);
    }
}

pub fn pair(mtu: usize, drop_a: Vec<usize>, drop_b: Vec<usize>) -> (Arc<Pipe>, Arc<Pipe>) {
    let (a_tx, b_rx) = unbounded_channel();
    let (b_tx, a_rx) = unbounded_channel();
    let a = Arc::new(Pipe {
        pacer: Pacer::default(),
        out: a_tx,
        inbox: Mutex::new(a_rx),
        mtu,
        sends: AtomicUsize::new(0),
        drop_sends: drop_a,
        delivered: AtomicUsize::new(0),
        cut: AtomicBool::new(false),
    });
    let b = Arc::new(Pipe {
        pacer: Pacer::default(),
        out: b_tx,
        inbox: Mutex::new(b_rx),
        mtu,
        sends: AtomicUsize::new(0),
        drop_sends: drop_b,
        delivered: AtomicUsize::new(0),
        cut: AtomicBool::new(false),
    });
    (a, b)
}

pub fn keypair() -> (Vec<u8>, Vec<u8>) {
    let kp = snow::Builder::new(shabdiz::handshake::PARAMS.parse().unwrap())
        .generate_keypair()
        .unwrap();
    (kp.private, kp.public)
}

pub fn arr32(v: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(v);
    a
}
