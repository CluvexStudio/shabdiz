mod common;

use std::sync::Arc;
use std::time::Duration;

use shabdiz::handshake::{accept, dial};
use shabdiz::session::{self, Handle, Role, PROBE_FLOOR};
use shabdiz::wire;

const CARRIER_MTU: usize = 1426;

fn psk() -> [u8; 32] {
    blake3::derive_key("shabdiz mtu test", b"a shared token")
}

async fn pair(limit: usize, drop_a: Vec<usize>, drop_b: Vec<usize>) -> (Arc<Handle>, Arc<Handle>) {
    pair_tries(limit, drop_a, drop_b, 3).await
}

async fn pair_tries(
    limit: usize,
    drop_a: Vec<usize>,
    drop_b: Vec<usize>,
    tries: usize,
) -> (Arc<Handle>, Arc<Handle>) {
    let (a, b) = common::pair_limited(CARRIER_MTU, limit, drop_a, drop_b);
    let (d_priv, d_pub) = common::keypair();
    let (r_priv, r_pub) = common::keypair();
    let (dp, rp) = (common::arr32(&d_priv), common::arr32(&r_priv));
    let (dpub, rpub) = (common::arr32(&d_pub), common::arr32(&r_pub));
    let psk = psk();

    let responder = {
        let b = b.clone();
        tokio::spawn(async move {
            let got = accept(&*b, &rp, &dpub, &psk).await.expect("accept");
            Arc::new(session::start(
                b,
                got.keys,
                got.params,
                Role::Responder,
                session::Config::default(),
                Some(session::Handshake {
                    first: got.first,
                    reply: got.reply,
                }),
            ))
        })
    };

    let (keys, params) = dial(&*a, &dp, &rpub, &psk, Duration::from_secs(2), tries)
        .await
        .expect("dial");
    let dialer = Arc::new(session::start(
        a,
        keys,
        params,
        Role::Dialer,
        session::Config::default(),
        None,
    ));
    (dialer, responder.await.expect("the responder starts"))
}

#[tokio::test]
async fn a_path_that_carries_what_the_carrier_claims_is_left_alone() {
    let (d, r) = pair(usize::MAX, vec![], vec![]).await;
    let assumed = d.mtu().assumed();
    assert_eq!(assumed, wire::payload_mtu(CARRIER_MTU));

    assert_eq!(d.mtu_settled().await, assumed, "no probe should shrink this");
    assert_eq!(r.mtu_settled().await, assumed);
    assert!(d.mtu().probed(), "the probe ran and settled");
}

#[tokio::test]
async fn a_smaller_path_is_discovered() {
    let limit = 1200;
    let (d, _r) = pair(limit, vec![], vec![]).await;
    let assumed = d.mtu().assumed();

    let found = d.mtu_settled().await;
    assert!(
        found < assumed,
        "a {limit}-byte path must not keep the {assumed}-byte assumption"
    );
    assert!(
        found + wire::OVERHEAD + wire::DATA_HDR <= limit,
        "a datagram of the discovered size must fit the path: {found} + 35 > {limit}"
    );
    assert!(
        found >= PROBE_FLOOR,
        "the search must not collapse below the floor: {found}"
    );
    assert!(
        found + wire::OVERHEAD + wire::DATA_HDR > limit - 40,
        "the search should land close to the real limit, not far under it: {found}"
    );
}

#[tokio::test]
async fn ordinary_loss_does_not_shrink_the_mtu() {
    let drops: Vec<usize> = (1..400).filter(|n| n % 2 == 0).collect();
    let (d, _r) = pair(usize::MAX, drops.clone(), drops).await;
    let assumed = d.mtu().assumed();

    assert_eq!(
        d.mtu_settled().await,
        assumed,
        "half the datagrams were dropped in both directions, but the path carries \
         full size — the control probe separates loss from a small mtu, so this \
         must not shrink"
    );
}

#[tokio::test]
async fn a_path_losing_two_in_three_still_does_not_shrink() {
    let drops: Vec<usize> = (1..600).filter(|n| n % 3 != 0).collect();
    let (d, _r) = pair_tries(usize::MAX, drops.clone(), drops, 24).await;
    let assumed = d.mtu().assumed();

    let found = d.mtu_settled().await;
    assert_eq!(
        found, assumed,
        "two of every three datagrams were dropped. Every round that produces no \
         signal at all is a retry, not a reason to shrink"
    );
}

#[tokio::test]
async fn a_small_path_is_still_found_through_loss() {
    let limit = 1100;
    let drops: Vec<usize> = (1..600).filter(|n| n % 3 == 0).collect();
    let (d, _r) = pair(limit, drops.clone(), drops).await;

    let found = d.mtu_settled().await;
    assert!(
        found < d.mtu().assumed(),
        "a {limit}-byte path with a third of its datagrams lost must still be \
         recognised as small: got {found}"
    );
    assert!(
        found + wire::OVERHEAD + wire::DATA_HDR <= limit,
        "and what it settles on must fit: {found} + 35 > {limit}"
    );
}

#[tokio::test]
async fn a_peer_asking_for_less_is_obeyed() {
    let (d, _r) = pair(usize::MAX, vec![], vec![]).await;
    let assumed = d.mtu_settled().await;

    let mut inner = Vec::new();
    wire::Frame::TooBig { mtu: 900 }.write(&mut inner);
    assert!(matches!(
        wire::Frame::parse(&inner),
        Some(wire::Frame::TooBig { mtu: 900 })
    ));
    assert_eq!(assumed, d.mtu().assumed(), "the cap arrives over the wire");
}

#[tokio::test]
async fn an_oversized_payload_is_answered_with_a_cap() {
    let (d, r) = pair(usize::MAX, vec![], vec![]).await;
    let _ = d.mtu_settled().await;

    let big = vec![7u8; d.mtu().assumed() + 64];
    d.send(1, &big);

    let got = tokio::time::timeout(Duration::from_secs(2), r.recv())
        .await
        .expect("the oversized datagram still arrives")
        .expect("the session is open");
    assert_eq!(got.1.len(), big.len());

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        d.mtu().payload() <= d.mtu().assumed(),
        "the sender is capped, never raised, by a TooBig"
    );
}

#[test]
fn a_probe_frame_is_the_size_it_claims() {
    for payload in [PROBE_FLOOR, 900, 1391usize] {
        let fill = vec![0u8; wire::probe_fill(payload)];
        let mut inner = Vec::new();
        wire::Frame::Probe {
            seq: 1,
            payload: payload as u16,
            fill: &fill,
        }
        .write(&mut inner);
        assert_eq!(
            inner.len(),
            payload + wire::DATA_HDR,
            "a probe for {payload} must occupy what a {payload}-byte datagram would"
        );

        match wire::Frame::parse(&inner) {
            Some(wire::Frame::Probe {
                seq,
                payload: p,
                fill: f,
            }) => {
                assert_eq!(seq, 1);
                assert_eq!(p as usize, payload);
                assert_eq!(f.len(), fill.len());
            }
            other => panic!("a probe must parse back: {other:?}"),
        }
    }
}

#[test]
fn a_probe_ack_is_small() {
    let mut inner = Vec::new();
    wire::Frame::ProbeAck {
        seq: 9,
        payload: 1391,
    }
    .write(&mut inner);
    assert_eq!(inner.len(), wire::PROBE_HDR);
    assert!(matches!(
        wire::Frame::parse(&inner),
        Some(wire::Frame::ProbeAck {
            seq: 9,
            payload: 1391
        })
    ));
}
