mod common;

use std::time::Duration;

use shabdiz::handshake::{accept, dial, Params};
use shabdiz::wire::{self, Frame, OVERHEAD};
use shabdiz::Carrier;

const MTU: usize = 1426;

fn psk() -> [u8; 32] {
    blake3::derive_key("shabdiz test psk", b"a shared token")
}

async fn handshake(
    drop_dialer: Vec<usize>,
    drop_peer: Vec<usize>,
) -> (
    anyhow::Result<(shabdiz::crypto::Keys, Params)>,
    anyhow::Result<shabdiz::handshake::Accepted>,
) {
    let (a, b) = common::pair(MTU, drop_dialer, drop_peer);
    let (dpriv, dpub) = common::keypair();
    let (ppriv, ppub) = common::keypair();
    let (dp, pp) = (common::arr32(&dpub), common::arr32(&ppub));
    let (dpriv, ppriv) = (common::arr32(&dpriv), common::arr32(&ppriv));

    let dialer =
        tokio::spawn(
            async move { dial(&*a, &dpriv, &pp, &psk(), Duration::from_millis(120), 5).await },
        );
    let peer = tokio::spawn(async move { accept(&*b, &ppriv, &dp, &psk()).await });
    (dialer.await.unwrap(), peer.await.unwrap())
}

#[tokio::test]
async fn both_ends_agree_on_keys_and_parameters() {
    let (d, p) = handshake(vec![], vec![]).await;
    let (dkeys, dparams) = d.expect("dial");
    let accepted = p.expect("accept");

    assert_eq!(
        dparams.cid, accepted.params.cid,
        "the dialler chooses the connection id"
    );
    assert_ne!(dparams.cid, [0; 8], "and never the reserved one");
    assert_eq!(dparams.payload_mtu, accepted.params.payload_mtu);
    assert_eq!(dparams.payload_mtu as usize, MTU - OVERHEAD - 3);

    let mut inner = Vec::new();
    Frame::Data {
        flow: 0,
        payload: b"first datagram",
    }
    .write(&mut inner);
    let mut dg = Vec::new();
    dkeys.seal(&inner, &mut dg);
    let (_, len) = accepted
        .keys
        .open(&mut dg)
        .expect("the accepting side opens it");
    assert_eq!(
        Frame::parse(shabdiz::crypto::Keys::inner(&dg, len)),
        Some(Frame::Data {
            flow: 0,
            payload: b"first datagram"
        })
    );
}

#[tokio::test]
async fn the_handshake_survives_a_lost_first_message() {
    let (d, p) = handshake(vec![1], vec![]).await;
    assert!(d.is_ok(), "the dialler retransmits: {:?}", d.err());
    assert!(p.is_ok());
}

#[tokio::test]
async fn a_lost_reply_is_answered_from_cache_when_the_dialler_retransmits() {
    let (a, b) = common::pair(MTU, vec![], vec![1]);
    let (dpriv, dpub) = common::keypair();
    let (ppriv, ppub) = common::keypair();
    let (dp, pp) = (common::arr32(&dpub), common::arr32(&ppub));
    let (dpriv, ppriv) = (common::arr32(&dpriv), common::arr32(&ppriv));

    let dialer =
        tokio::spawn(
            async move { dial(&*a, &dpriv, &pp, &psk(), Duration::from_millis(120), 5).await },
        );
    let peer = tokio::spawn(async move {
        let accepted = accept(&*b, &ppriv, &dp, &psk()).await?;
        let mut buf = vec![0u8; 2048];
        while let Ok(n) = b.recv(&mut buf).await {
            match wire::parse_handshake(&buf[..n]) {
                Some((wire::HS_MSG1, _)) => b.send(&accepted.reply).await?,
                _ => break,
            }
        }
        Ok::<_, anyhow::Error>(accepted.params)
    });

    let (dkeys, dparams) = dialer.await.unwrap().expect("the dialler gets its session");
    let pparams = peer
        .await
        .unwrap()
        .expect("the accepting side keeps its own");
    assert_eq!(
        dparams, pparams,
        "one handshake, one agreement, despite the loss"
    );
    let _ = dkeys;
}

#[tokio::test]
async fn an_accepted_handshake_keeps_its_reply_so_a_lost_one_can_be_resent() {
    let (_, p) = handshake(vec![], vec![]).await;
    let accepted = p.expect("accept");
    assert!(
        shabdiz::wire::is_handshake(&accepted.reply),
        "the cached reply is a handshake datagram, ready to send again"
    );
}

#[tokio::test]
async fn a_dialler_with_the_wrong_token_never_gets_a_session() {
    let (a, b) = common::pair(MTU, vec![], vec![]);
    let (dpriv, dpub) = common::keypair();
    let (ppriv, ppub) = common::keypair();
    let (dp, pp) = (common::arr32(&dpub), common::arr32(&ppub));
    let (dpriv, ppriv) = (common::arr32(&dpriv), common::arr32(&ppriv));

    let wrong = blake3::derive_key("shabdiz test psk", b"not the token");
    let b2 = b.clone();
    let dialer =
        tokio::spawn(
            async move { dial(&*a, &dpriv, &pp, &wrong, Duration::from_millis(60), 2).await },
        );
    let peer = tokio::spawn(async move { accept(&*b2, &ppriv, &dp, &psk()).await });

    assert!(
        dialer.await.unwrap().is_err(),
        "a wrong psk must not produce a session"
    );
    assert_eq!(b.sends(), 1, "exactly one reply, and nothing follows it");
    peer.abort();
}

#[tokio::test]
async fn the_accepting_side_sends_nothing_before_it_has_heard_from_the_dialler() {
    let (_a, b) = common::pair(MTU, vec![], vec![]);
    let (ppriv, _) = common::keypair();
    let (_, dpub) = common::keypair();
    let (ppriv, dp) = (common::arr32(&ppriv), common::arr32(&dpub));
    let b2 = b.clone();
    let peer = tokio::spawn(async move { accept(&*b2, &ppriv, &dp, &psk()).await });
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(b.sends(), 0, "it must not probe, not even once");
    peer.abort();
}

#[tokio::test]
async fn a_handshake_from_an_unexpected_static_key_is_refused() {
    let (a, b) = common::pair(MTU, vec![], vec![]);
    let (dpriv, _dpub) = common::keypair();
    let (ppriv, ppub) = common::keypair();
    let (_, stranger_pub) = common::keypair();
    let pp = common::arr32(&ppub);
    let (dpriv, ppriv) = (common::arr32(&dpriv), common::arr32(&ppriv));
    let expect = common::arr32(&stranger_pub);

    let dialer =
        tokio::spawn(
            async move { dial(&*a, &dpriv, &pp, &psk(), Duration::from_millis(60), 1).await },
        );
    let peer = tokio::spawn(async move { accept(&*b, &ppriv, &expect, &psk()).await });

    assert!(
        peer.await.unwrap().is_err(),
        "the pinned key is checked, not assumed"
    );
    assert!(dialer.await.unwrap().is_err());
}

#[tokio::test]
async fn junk_gets_silence() {
    let (a, b) = common::pair(MTU, vec![], vec![]);
    let (ppriv, _) = common::keypair();
    let (_, dpub) = common::keypair();
    let (ppriv, dp) = (common::arr32(&ppriv), common::arr32(&dpub));
    let b2 = b.clone();
    let peer = tokio::spawn(async move { accept(&*b2, &ppriv, &dp, &psk()).await });

    let mut junk = Vec::new();
    for i in 0..5u8 {
        wire::handshake_datagram(wire::HS_MSG1, &[i; 96], &mut junk);
        a.send(&junk).await.unwrap();
    }
    a.send(b"not even a handshake").await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    assert_eq!(b.sends(), 0, "a prober must get silence");
    assert!(
        !peer.is_finished(),
        "and the accepting side keeps waiting for a real peer"
    );
    peer.abort();
}
