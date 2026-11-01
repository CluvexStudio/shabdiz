use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ring::rand::SecureRandom;
use snow::Builder;

use super::crypto::Keys;
use super::wire::{self, Cid, HS_MSG1, HS_MSG2};
use super::{Carrier, KEEPALIVE_SECS, PROLOGUE};

pub const PARAMS: &str = "Noise_IKpsk2_25519_AESGCM_BLAKE2s";

pub const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub cid: Cid,
    pub payload_mtu: u16,
    pub keepalive_secs: u8,
}

impl Params {
    pub fn propose(carrier_mtu: usize) -> Result<Params> {
        let mut cid: Cid = [0; 8];
        ring::rand::SystemRandom::new()
            .fill(&mut cid)
            .map_err(|_| anyhow!("no system randomness for a connection id"))?;
        if cid == wire::CID_HANDSHAKE {
            cid[0] = 1;
        }
        Ok(Params {
            cid,
            payload_mtu: wire::payload_mtu(carrier_mtu).min(u16::MAX as usize) as u16,
            keepalive_secs: KEEPALIVE_SECS as u8,
        })
    }

    fn write(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(12);
        v.push(VERSION);
        v.extend_from_slice(&self.cid);
        v.extend_from_slice(&self.payload_mtu.to_be_bytes());
        v.push(self.keepalive_secs);
        v
    }

    fn parse(d: &[u8]) -> Result<Params> {
        if d.len() < 12 {
            bail!("handshake payload is {} bytes, want 12", d.len());
        }
        if d[0] != VERSION {
            bail!(
                "peer speaks shabdiz version {}, this build speaks {VERSION}",
                d[0]
            );
        }
        let mut cid: Cid = [0; 8];
        cid.copy_from_slice(&d[1..9]);
        Ok(Params {
            cid,
            payload_mtu: u16::from_be_bytes([d[9], d[10]]),
            keepalive_secs: d[11],
        })
    }
}

pub struct Accepted {
    pub keys: Keys,
    pub params: Params,
    pub reply: Vec<u8>,
    pub first: Vec<u8>,
}

fn builder(prologue: &'static [u8]) -> Result<Builder<'static>> {
    Ok(Builder::new(PARAMS.parse().context("noise params")?).prologue(prologue)?)
}

fn hs_err(e: snow::Error) -> anyhow::Error {
    anyhow!("shabdiz handshake failed ({e}); both ends need the same token and pinned keys")
}

pub async fn dial(
    carrier: &dyn Carrier,
    local_priv: &[u8; 32],
    peer_pub: &[u8; 32],
    psk: &[u8; 32],
    reply_timeout: Duration,
    tries: usize,
) -> Result<(Keys, Params)> {
    let mut hs = builder(PROLOGUE)?
        .local_private_key(local_priv)?
        .remote_public_key(peer_pub)?
        .psk(2, psk)?
        .build_initiator()?;

    let want = Params::propose(carrier.mtu())?;
    let mut msg = [0u8; 512];
    let n = hs.write_message(&want.write(), &mut msg).map_err(hs_err)?;
    let mut datagram = Vec::with_capacity(wire::CID_LEN + 1 + n);
    wire::handshake_datagram(HS_MSG1, &msg[..n], &mut datagram);

    let mut buf = vec![0u8; 2048];
    for attempt in 1..=tries.max(1) {
        carrier
            .send(&datagram)
            .await
            .context("sending the first handshake message")?;
        let deadline = tokio::time::Instant::now() + reply_timeout;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            let got = match tokio::time::timeout(left, carrier.recv(&mut buf)).await {
                Err(_) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e).context("carrier failed during the handshake"),
            };
            let Some((kind, noise)) = wire::parse_handshake(&buf[..got]) else {
                continue;
            };
            if kind != HS_MSG2 {
                continue;
            }
            let mut payload = [0u8; 512];
            let plen = match hs.read_message(noise, &mut payload) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let theirs = Params::parse(&payload[..plen])?;
            if !hs.is_handshake_finished() {
                bail!("peer answered but the handshake did not complete");
            }
            let (i2r, r2i) = hs.dangerously_get_raw_split();
            let params = Params {
                cid: want.cid,
                payload_mtu: want.payload_mtu.min(theirs.payload_mtu),
                keepalive_secs: want.keepalive_secs,
            };
            return Ok((Keys::new(params.cid, i2r, r2i, true), params));
        }
        tracing::debug!(
            "shabdiz: no answer to handshake attempt {attempt}/{tries}, retransmitting"
        );
    }
    bail!("no answer to {tries} handshake attempts; is the other end running and are the keys pinned?")
}

pub async fn accept(
    carrier: &dyn Carrier,
    local_priv: &[u8; 32],
    expect_peer: &[u8; 32],
    psk: &[u8; 32],
) -> Result<Accepted> {
    let mut buf = vec![0u8; 2048];
    loop {
        let got = carrier
            .recv(&mut buf)
            .await
            .context("waiting for a handshake")?;
        let Some((kind, noise)) = wire::parse_handshake(&buf[..got]) else {
            continue;
        };
        if kind != HS_MSG1 {
            continue;
        }
        let mut hs = builder(PROLOGUE)?
            .local_private_key(local_priv)?
            .psk(2, psk)?
            .build_responder()?;
        let mut payload = [0u8; 512];
        let plen = match hs.read_message(noise, &mut payload) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let theirs = Params::parse(&payload[..plen])?;

        match hs.get_remote_static() {
            Some(k) if k == expect_peer => {}
            Some(_) => bail!("handshake from an unexpected static key (peer_public mismatch)"),
            None => bail!("handshake carried no static key"),
        }

        let mine = Params::propose(carrier.mtu())?;
        let mut msg = [0u8; 512];
        let n = hs
            .write_message(
                &Params {
                    cid: theirs.cid,
                    ..mine
                }
                .write(),
                &mut msg,
            )
            .map_err(hs_err)?;
        let mut reply = Vec::with_capacity(wire::CID_LEN + 1 + n);
        wire::handshake_datagram(HS_MSG2, &msg[..n], &mut reply);
        carrier
            .send(&reply)
            .await
            .context("answering the handshake")?;

        if !hs.is_handshake_finished() {
            bail!("handshake did not complete after the reply");
        }
        let (i2r, r2i) = hs.dangerously_get_raw_split();
        let params = Params {
            cid: theirs.cid,
            payload_mtu: theirs.payload_mtu.min(mine.payload_mtu),
            keepalive_secs: theirs.keepalive_secs,
        };
        return Ok(Accepted {
            keys: Keys::new(params.cid, i2r, r2i, false),
            params,
            reply,
            first: buf[..got].to_vec(),
        });
    }
}
