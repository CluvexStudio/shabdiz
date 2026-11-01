mod common;

use std::sync::Arc;
use std::time::Duration;

use shabdiz::carrier::udp::Udp;
use shabdiz::carrier::Carrier;
use shabdiz::handshake::{accept, dial};
use shabdiz::session::{self, Handle, Role};

const MTU: usize = 1426;

fn psk() -> [u8; 32] {
    blake3::derive_key("shabdiz session test", b"a shared token")
}

async fn pair(ping: Duration) -> (Arc<Handle>, Arc<Handle>) {
    pair_with(ping, Duration::from_secs(30)).await
}

async fn pair_with(ping: Duration, idle: Duration) -> (Arc<Handle>, Arc<Handle>) {
    let (d, r, _, _, _) = pair_full(ping, idle).await;
    (d, r)
}

async fn pair_full(
    ping: Duration,
    idle: Duration,
) -> (
    Arc<Handle>,
    Arc<Handle>,
    Arc<common::Pipe>,
    Arc<common::Pipe>,
    Vec<u8>,
) {
    pair_dropping(ping, idle, vec![], vec![]).await
}

async fn pair_dropping(
    ping: Duration,
    idle: Duration,
    drop_a: Vec<usize>,
    drop_b: Vec<usize>,
) -> (
    Arc<Handle>,
    Arc<Handle>,
    Arc<common::Pipe>,
    Arc<common::Pipe>,
    Vec<u8>,
) {
    let (ca, cb) = common::pair(MTU, drop_a, drop_b);
    let (dpriv, dpub) = common::keypair();
    let (ppriv, ppub) = common::keypair();
    let (dp, pp) = (common::arr32(&dpub), common::arr32(&ppub));
    let (dpriv, ppriv) = (common::arr32(&dpriv), common::arr32(&ppriv));

    let cfg = session::Config {
        ping,
        idle,
        ..Default::default()
    };
    let accepting = {
        let cb = cb.clone();
        tokio::spawn(async move { accept(&*cb, &ppriv, &dp, &psk()).await })
    };
    let (dkeys, dparams) = dial(&*ca, &dpriv, &pp, &psk(), Duration::from_millis(200), 5)
        .await
        .expect("dial");
    let a = accepting.await.unwrap().expect("accept");

    let dialer = session::start(ca.clone(), dkeys, dparams, Role::Dialer, cfg, None);
    let first = a.first.clone();
    let responder = session::start(
        cb.clone(),
        a.keys,
        a.params,
        Role::Responder,
        cfg,
        Some(session::Handshake {
            first: a.first,
            reply: a.reply,
        }),
    );
    (Arc::new(dialer), Arc::new(responder), ca, cb, first)
}

async fn closes_within(h: &Arc<Handle>, limit: Duration) -> bool {
    let deadline = std::time::Instant::now() + limit;
    while std::time::Instant::now() < deadline {
        if h.is_closed() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    h.is_closed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_datagram_crosses_in_each_direction() {
    let (d, r) = pair(Duration::from_secs(60)).await;

    d.send(3, b"from the dialler");
    let (flow, payload) = tokio::time::timeout(Duration::from_secs(2), r.recv())
        .await
        .expect("the responder receives it")
        .expect("session is live");
    assert_eq!((flow, &payload[..]), (3, &b"from the dialler"[..]));

    r.send(9, b"and back again");
    let (flow, payload) = tokio::time::timeout(Duration::from_secs(2), d.recv())
        .await
        .expect("the dialler receives the answer")
        .expect("session is live");
    assert_eq!((flow, &payload[..]), (9, &b"and back again"[..]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_responder_answers_the_keepalive_so_the_flow_stays_two_way() {
    let (d, r) = pair(Duration::from_millis(20)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (ds, rs) = (d.snapshot(), r.snapshot());
    assert!(ds.tx_datagrams >= 5, "the dialler keeps pinging: {ds:?}");
    assert!(
        rs.tx_datagrams >= 5,
        "and the responder keeps answering: {rs:?}"
    );
    assert!(
        rs.rx_datagrams >= 5,
        "both directions carry traffic: {rs:?}"
    );
    assert!(ds.rx_datagrams >= 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_round_trip_and_jitter_are_measured_from_the_keepalive() {
    let (d, r) = pair(Duration::from_millis(20)).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    let ds = d.snapshot();
    assert!(ds.rtt_us > 0, "the dialler measures a round trip: {ds:?}");
    assert!(
        ds.rtt_us < 1_000_000,
        "and it is a plausible one: {} us",
        ds.rtt_us
    );
    assert!(r.snapshot().rx_datagrams > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_is_lost_on_a_clean_carrier() {
    let (d, r) = pair(Duration::from_millis(20)).await;
    for i in 0..200u32 {
        d.send(1, &i.to_be_bytes());
    }
    let mut got = 0;
    while got < 200 {
        match tokio::time::timeout(Duration::from_secs(2), r.recv()).await {
            Ok(Some(_)) => got += 1,
            _ => break,
        }
    }
    assert_eq!(got, 200, "every datagram arrived");
    let rs = r.snapshot();
    assert_eq!(rs.lost, 0, "and the counter agrees: {rs:?}");
    assert_eq!(rs.rejected, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_that_goes_silent_closes_the_session_rather_than_looking_connected() {
    let (d, r, ca, cb, _) = pair_full(Duration::from_millis(20), Duration::from_millis(150)).await;
    assert!(!d.is_closed());

    ca.cut();
    cb.cut();
    d.send(1, b"into the void");
    tokio::time::sleep(Duration::from_millis(600)).await;

    assert!(d.is_closed(), "the dialler notices the silence");
    assert!(r.is_closed(), "and so does the responder");
    assert!(
        d.recv().await.is_none(),
        "and the handle reports it rather than hanging"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_over_real_sockets_carries_both_directions() {
    let entry = Udp::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind the entry");
    let entry_addr = entry.local_addr().unwrap();
    let exit = Udp::connect("127.0.0.1:0".parse().unwrap(), entry_addr)
        .await
        .expect("bind the exit");
    let (entry, exit): (Arc<dyn shabdiz::Carrier>, Arc<dyn shabdiz::Carrier>) =
        (Arc::new(entry), Arc::new(exit));

    let (dpriv, dpub) = common::keypair();
    let (ppriv, ppub) = common::keypair();
    let (dp, pp) = (common::arr32(&dpub), common::arr32(&ppub));
    let (dpriv, ppriv) = (common::arr32(&dpriv), common::arr32(&ppriv));

    let accepting = {
        let entry = entry.clone();
        tokio::spawn(async move { accept(&*entry, &ppriv, &dp, &psk()).await })
    };
    let (dkeys, dparams) = dial(&*exit, &dpriv, &pp, &psk(), Duration::from_millis(500), 5)
        .await
        .expect("the exit dials, as the protocol requires");
    let a = accepting.await.unwrap().expect("the entry accepts");

    let cfg = session::Config {
        ping: Duration::from_millis(20),
        ..Default::default()
    };
    let d = session::start(exit, dkeys, dparams, Role::Dialer, cfg, None);
    let r = session::start(
        entry,
        a.keys,
        a.params,
        Role::Responder,
        cfg,
        Some(session::Handshake {
            first: a.first,
            reply: a.reply,
        }),
    );

    d.send(1, b"down");
    let (_, got) = tokio::time::timeout(Duration::from_secs(2), r.recv())
        .await
        .expect("the entry receives")
        .unwrap();
    assert_eq!(&got[..], b"down");

    r.send(1, b"up");
    let (_, got) = tokio::time::timeout(Duration::from_secs(2), d.recv())
        .await
        .expect("the exit receives — this is the direction that was silent")
        .unwrap();
    assert_eq!(&got[..], b"up");

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        r.snapshot().tx_datagrams >= 5,
        "the responder answers: {:?}",
        r.snapshot()
    );
    assert!(d.snapshot().rtt_us > 0, "and the round trip is measured");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_first_message_is_answered_from_cache() {
    let (_d, r, ca, cb, first) =
        pair_full(Duration::from_secs(300), Duration::from_secs(300)).await;
    let before = cb.sends();
    ca.send(&first).await.expect("resend the first message");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        cb.sends() > before,
        "the responder resends its cached answer"
    );
    assert!(
        !r.is_closed(),
        "and does not throw away keys that are still good"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_different_first_message_ends_the_session() {
    let (_d, r, ca, _cb, first) =
        pair_full(Duration::from_secs(300), Duration::from_secs(300)).await;
    let mut fresh = first.clone();
    *fresh.last_mut().unwrap() ^= 1;
    tokio::time::sleep(Duration::from_millis(500)).await;
    ca.send(&fresh)
        .await
        .expect("a first message from a restarted peer");
    assert!(
        closes_within(&r, Duration::from_secs(6)).await,
        "the responder must end the session instead of answering from cache for ever"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_first_message_cannot_kill_a_live_session() {
    let (d, r, ca, _cb, first) =
        pair_full(Duration::from_millis(100), Duration::from_secs(300)).await;
    let mut forged = first.clone();
    *forged.last_mut().unwrap() ^= 1;
    ca.send(&forged).await.expect("send the forged message");
    for _ in 0..12 {
        d.send(1, b"still here");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        !r.is_closed(),
        "authenticated traffic outweighs an unauthenticated claim"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn junk_does_not_keep_a_dead_session_alive() {
    let (_d, r, ca, _cb, _) = pair_full(Duration::from_secs(300), Duration::from_millis(400)).await;
    let pelt = {
        let ca = ca.clone();
        tokio::spawn(async move {
            for _ in 0..40 {
                let _ = ca.send(&[0xAA; 64]).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
    };
    assert!(
        closes_within(&r, Duration::from_secs(3)).await,
        "a session with no authenticated traffic must time out however much junk arrives"
    );
    pelt.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_ends_report_what_they_lose_not_just_the_dialler() {
    let (d, r, _, _, _) = pair_dropping(
        Duration::from_millis(100),
        Duration::from_secs(30),
        (8..60).collect(),
        vec![],
    )
    .await;
    for _ in 0..80 {
        d.send(1, b"payload");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (ds, rs) = (d.snapshot(), r.snapshot());
    assert!(rs.lost > 0, "the responder must see the gaps: {rs:?}");
    assert!(
        ds.peer_lost > 0,
        "and the dialler must be told about them, or its pacer is blind: {ds:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pacer_is_told_about_now_and_not_about_the_whole_session() {
    let (d, r, ca, _cb, _) = pair_dropping(
        Duration::from_millis(100),
        Duration::from_secs(30),
        (8..40).collect(),
        vec![],
    )
    .await;
    for _ in 0..40 {
        d.send(1, b"payload");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        r.snapshot().lost > 0,
        "the responder must have seen the early gaps"
    );

    for _ in 0..120 {
        d.send(1, b"payload");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let s = r.snapshot();
    let lifetime = s.lost as f64 / (s.lost + s.highest.saturating_sub(s.lost)) as f64;
    assert!(
        lifetime > 0.02,
        "the lifetime average is still bad: {lifetime:.3}"
    );
    assert_eq!(
        ca.pacer().rate_pps(),
        0,
        "yet the dialler's pacer must be unthrottled, because every recent interval was clean"
    );
}
