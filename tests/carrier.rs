use std::time::Duration;

#[cfg(target_os = "linux")]
use shabdiz::carrier::l2frame;
use shabdiz::carrier::{tcp::Tcp, udp::Udp, Batch, Carrier, Pacer, BATCH, SAFE_BURST};

#[test]
fn a_batch_keeps_its_datagrams_whole_and_in_order() {
    let mut b = Batch::new(4, 100);
    assert!(b.is_empty());
    assert!(b.push(b"one"));
    assert!(b.push(b"two"));
    assert!(b.push(&[0u8; 100]), "exactly the stride fits");
    assert!(!b.push(&[0u8; 101]), "one byte over does not");
    assert_eq!(b.len(), 3);
    assert_eq!(b.get(0), Some(&b"one"[..]));
    assert_eq!(b.get(1), Some(&b"two"[..]));
    assert_eq!(b.get(2).map(|d| d.len()), Some(100));
    assert_eq!(b.get(3), None);
    assert!(b.push(b"four"));
    assert!(b.is_full());
    assert!(
        !b.push(b"five"),
        "a full batch refuses rather than overwriting"
    );
    b.clear();
    assert!(b.is_empty());
}

#[test]
fn offload_needs_equal_segments_bar_the_last() {
    let mut b = Batch::new(8, 1200);
    assert!(b.is_gso_shaped(), "an empty batch is trivially shaped");
    b.push(&[1u8; 1200]);
    b.push(&[2u8; 1200]);
    assert!(b.is_gso_shaped());
    b.push(&[3u8; 400]);
    assert!(b.is_gso_shaped(), "a short final datagram is allowed");

    let mut scratch = Vec::new();
    let (seg, bytes) = b.gso_payload(&mut scratch).expect("shaped");
    assert_eq!(seg, 1200);
    assert_eq!(bytes.len(), 1200 * 2 + 400);

    let mut bad = Batch::new(8, 1200);
    bad.push(&[1u8; 1200]);
    bad.push(&[2u8; 400]);
    bad.push(&[3u8; 1200]);
    assert!(!bad.is_gso_shaped());
    assert!(bad.gso_payload(&mut scratch).is_none());
}

#[test]
fn a_batch_hands_out_groups_no_larger_than_the_pacer_allows() {
    let mut b = Batch::new(32, 100);
    for i in 0..10u8 {
        b.push(&[i; 100]);
    }
    let groups: Vec<_> = b.groups(SAFE_BURST).collect();
    assert_eq!(groups.len(), 5, "ten datagrams in groups of two");
    assert_eq!(groups[0], (0, 2));
    assert_eq!(groups[4], (8, 10));

    let mut scratch = Vec::new();
    let (seg, bytes) = b
        .group_payload(groups[1], &mut scratch)
        .expect("shaped group");
    assert_eq!(seg, 100);
    assert_eq!(bytes.len(), 200);
    assert_eq!(
        &bytes[..1],
        &[2u8],
        "the group starts where it says it does"
    );

    let groups: Vec<_> = b.groups(3).collect();
    assert_eq!(groups.last(), Some(&(9, 10)));
}

#[test]
fn a_coalesced_receive_splits_back_into_datagrams() {
    let mut b = Batch::new(8, 1200);
    let mut run = Vec::new();
    run.extend_from_slice(&[1u8; 1200]);
    run.extend_from_slice(&[2u8; 1200]);
    run.extend_from_slice(&[3u8; 500]);
    assert_eq!(b.split_coalesced(&run, 1200), 3);
    assert_eq!(b.get(0).map(|d| d.len()), Some(1200));
    assert_eq!(b.get(2).map(|d| d.len()), Some(500));
    assert_eq!(
        b.split_coalesced(&run, 0),
        0,
        "a zero stride splits into nothing"
    );
}

#[test]
fn the_pacer_defaults_to_what_measured_safe_and_adapts_from_there() {
    let p = Pacer::default();
    assert_eq!(
        p.burst(),
        SAFE_BURST,
        "the default must work without tuning"
    );

    p.set_burst(16);
    p.observe(0.30);
    assert_eq!(p.burst(), 8);
    p.observe(0.30);
    assert_eq!(p.burst(), 4);

    let q = Pacer::new(4);
    q.observe(0.0);
    assert_eq!(q.burst(), 5);
    q.observe(0.0);
    assert_eq!(q.burst(), 6);

    let lossy = Pacer::new(SAFE_BURST);
    lossy.observe(1.0);
    assert_eq!(
        lossy.burst(),
        SAFE_BURST,
        "shrinking past this buys nothing and costs rate"
    );
    let wide = Pacer::new(BATCH);
    wide.observe(0.0);
    assert_eq!(wide.burst(), BATCH);
}

#[tokio::test]
async fn persistent_loss_turns_into_a_rate_limit_once_the_burst_is_small() {
    let p = Pacer::new(SAFE_BURST);
    p.enable_auto_rate();
    assert_eq!(p.rate_pps(), 0, "no limit until something earns one");

    for _ in 0..40 {
        p.admit(25).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let seen = p.achieved_pps();
    assert!(seen > 0, "the pacer must know what rate it was passing");

    p.observe(0.40);
    let limited = p.rate_pps();
    assert!(
        limited > 0,
        "heavy loss at a minimum burst must produce a rate limit"
    );
    assert!(
        limited <= seen,
        "and it must be below what was going out: {limited} vs {seen}"
    );

    for _ in 0..4 {
        for _ in 0..30 {
            p.admit(5).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        p.observe(0.0);
    }
    let after = p.rate_pps();
    assert!(
        after == 0 || after > limited,
        "quiet must lift the limit, got {after}"
    );

    p.set_rate_pps(4_000);
    for _ in 0..3 {
        p.admit(1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    p.observe(0.0);
    assert_eq!(
        p.rate_pps(),
        0,
        "a limit nothing is pressing against is dropped"
    );
}

#[tokio::test]
async fn the_rate_limit_holds_an_average_a_sleep_per_group_could_not() {
    let p = Pacer::new(4);
    p.set_rate_pps(4_000);
    let t = std::time::Instant::now();
    for _ in 0..500 {
        p.admit(4).await;
    }
    let took = t.elapsed();
    assert!(
        took >= Duration::from_millis(400) && took <= Duration::from_millis(750),
        "2000 datagrams at 4000/s should take about half a second, took {took:?}"
    );
}

#[tokio::test]
async fn the_pacer_waits_only_when_it_has_been_given_a_reason_to() {
    let p = Pacer::new(4);
    p.set_gap(Duration::from_millis(5));
    let t = std::time::Instant::now();
    for _ in 0..4 {
        p.admit(4).await;
    }
    assert!(
        t.elapsed() >= Duration::from_millis(10),
        "four groups, 5 ms apart"
    );

    let q = Pacer::new(4);
    let t = std::time::Instant::now();
    for _ in 0..100 {
        q.admit(32).await;
    }
    assert!(
        t.elapsed() < Duration::from_millis(20),
        "unpaced must stay unpaced"
    );
}

#[tokio::test]
async fn the_tcp_carrier_round_trips_datagrams_and_keeps_their_boundaries() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move { Tcp::accept(&l).await.unwrap() });
    let client = Tcp::connect(addr).await.unwrap();
    let server = server.await.unwrap();

    for d in [&b"first"[..], &[0u8; 1400], &b"x"[..]] {
        client.send(d).await.unwrap();
    }
    let mut buf = vec![0u8; 2048];
    let n = server.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"first");
    assert_eq!(server.recv(&mut buf).await.unwrap(), 1400);
    let n = server.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"x");

    assert!(
        client.send(&[0u8; 1401]).await.is_err(),
        "a datagram past the carrier's limit is refused, not truncated"
    );
}

#[tokio::test]
async fn the_tcp_carrier_sends_a_whole_batch_in_one_write() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move { Tcp::accept(&l).await.unwrap() });
    let client = Tcp::connect(addr).await.unwrap();
    let server = server.await.unwrap();

    let mut batch = Batch::new(8, 1200);
    for i in 0..5u8 {
        batch.push(&vec![i; 1200]);
    }
    assert_eq!(client.send_batch(&batch).await.unwrap(), 5);

    let mut buf = vec![0u8; 2048];
    for i in 0..5u8 {
        let n = server.recv(&mut buf).await.unwrap();
        assert_eq!(n, 1200);
        assert_eq!(buf[0], i, "and they arrive in order");
    }
}

#[tokio::test]
async fn the_udp_carrier_round_trips_and_reports_its_offload() {
    let a = Udp::connect(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:1".parse().unwrap(),
    )
    .await
    .unwrap();
    let a_addr = a.local_addr().unwrap();
    let b = Udp::connect("127.0.0.1:0".parse().unwrap(), a_addr)
        .await
        .unwrap();
    let b_addr = b.local_addr().unwrap();
    let a = Udp::connect(a_addr, b_addr).await;
    assert!(a.is_err(), "the port is taken, and that is reported");

    let c = Udp::connect("127.0.0.1:0".parse().unwrap(), b_addr)
        .await
        .unwrap();
    c.send(b"hello over udp").await.unwrap();
    let mut buf = vec![0u8; 2048];
    let n = b.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello over udp");
    assert!(c.mtu() >= 1200, "a usable datagram size");
    assert!(
        c.max_segments() >= 1,
        "offload is reported, whether or not it is available"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn a_crafted_frame_carries_its_payload_with_valid_checksums() {
    let f = l2frame::Frame {
        src_mac: [0x52, 0x54, 0, 1, 2, 3],
        dst_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        src_ip: "10.0.0.1".parse().unwrap(),
        dst_ip: "10.0.0.2".parse().unwrap(),
        sport: 30001,
        dport: 40002,
        seq: 1234,
        ack: 0,
        tsval: 99,
        ip_id: 7,
    };
    let payload = b"shabdiz over crafted tcp";
    let mut out = Vec::new();
    l2frame::craft(&f, payload, 0, &mut out);

    let frame = &out[l2frame::VNET_HDR..];
    let ip = &frame[l2frame::ETH_HDR..];
    assert_eq!(ip[0], 0x45);
    assert_eq!(ip[9], 6, "TCP");
    assert_eq!(
        l2frame::checksum(&ip[..l2frame::IP4_HDR], 0),
        0,
        "IP header checksum"
    );
    let tcp = &ip[l2frame::IP4_HDR..];
    let seg_len = tcp.len() as u16;
    assert_eq!(
        l2frame::checksum(tcp, l2frame::pseudo_sum(f.src_ip, f.dst_ip, seg_len)),
        0,
        "TCP checksum over the pseudo-header"
    );

    let p = l2frame::parse(&out, true, f.dport, f.sport).expect("our own frame parses");
    assert_eq!(p.payload, payload);
    assert_eq!(p.gso_size, 0, "nothing was coalesced");
}

#[test]
#[cfg(target_os = "linux")]
fn an_offloaded_frame_leaves_the_checksum_for_the_kernel_to_finish() {
    let f = l2frame::Frame {
        src_mac: [0; 6],
        dst_mac: [0; 6],
        src_ip: "10.0.0.1".parse().unwrap(),
        dst_ip: "10.0.0.2".parse().unwrap(),
        sport: 1,
        dport: 2,
        seq: 0,
        ack: 0,
        tsval: 0,
        ip_id: 0,
    };
    let mut plain = Vec::new();
    let mut offloaded = Vec::new();
    let payload = [7u8; 2400];
    l2frame::craft(&f, &payload, 0, &mut plain);
    l2frame::craft(&f, &payload, 1200, &mut offloaded);

    assert_eq!(&plain[..l2frame::VNET_HDR], &[0u8; l2frame::VNET_HDR]);
    assert_eq!(offloaded[0], 1, "needs checksum");
    assert_eq!(offloaded[1], 1, "TCPv4 segmentation");
    assert_eq!(
        u16::from_le_bytes([offloaded[4], offloaded[5]]),
        1200,
        "segment size"
    );
    assert_eq!(
        u16::from_le_bytes([offloaded[8], offloaded[9]]),
        16,
        "the checksum sits 16 bytes into the TCP header"
    );

    let (a, b) = (&plain[l2frame::VNET_HDR..], &offloaded[l2frame::VNET_HDR..]);
    let csum = l2frame::ETH_HDR + l2frame::IP4_HDR + 16;
    assert_eq!(a[..csum], b[..csum]);
    assert_ne!(a[csum..csum + 2], b[csum..csum + 2]);
    assert_eq!(a[csum + 2..], b[csum + 2..]);
}

#[tokio::test]
async fn a_rate_limit_recovers_instead_of_parking_between_the_thresholds() {
    let p = Pacer::new(SAFE_BURST);
    p.enable_auto_rate();
    p.set_rate_pps(715);
    for _ in 0..5 {
        for _ in 0..30 {
            p.admit(5).await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        p.observe(0.003);
    }
    assert!(
        p.rate_pps() > 715,
        "0.3% loss must let the rate back up, not freeze it"
    );
}

#[tokio::test]
async fn the_rate_is_cut_once_and_then_given_time_to_be_measured() {
    let p = Pacer::new(SAFE_BURST);
    p.enable_auto_rate();
    for _ in 0..30 {
        p.admit(25).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    p.observe(0.40);
    let first = p.rate_pps();
    assert!(first > 0, "the first bad report cuts the rate");

    for _ in 0..4 {
        for _ in 0..30 {
            p.admit(25).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        p.observe(0.40);
    }
    assert_eq!(
        p.rate_pps(),
        first,
        "and is left alone until the reports catch up"
    );
}

#[tokio::test]
async fn a_single_group_batch_is_still_charged_for() {
    let p = Pacer::new(BATCH);
    p.set_rate_pps(2_000);
    let t = std::time::Instant::now();
    for _ in 0..20 {
        p.admit(BATCH).await;
    }
    assert!(
        t.elapsed() >= Duration::from_millis(250),
        "one group per batch must still be paced, took {:?}",
        t.elapsed()
    );
}
