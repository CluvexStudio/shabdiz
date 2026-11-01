use shabdiz::wire::*;

#[test]
fn head_round_trip() {
    let h = Head {
        cid: [9, 8, 7, 6, 5, 4, 3, 2],
        ctr: 0x0102_0304_0506_0708,
    };
    let mut out = Vec::new();
    h.write(&mut out);
    out.resize(OVERHEAD, 0);
    assert_eq!(Head::parse(&out), Some(h));
}

#[test]
fn a_datagram_shorter_than_its_own_overhead_is_not_a_head() {
    assert_eq!(Head::parse(&[0u8; OVERHEAD - 1]), None);
}

#[test]
fn session_frames_round_trip() {
    let cases: Vec<Frame> = vec![
        Frame::Data {
            flow: 0,
            payload: b"hysteria2 datagram",
        },
        Frame::Data {
            flow: 7,
            payload: b"",
        },
        Frame::Ping { tx_ts: 1 },
        Frame::Pong {
            echo_ts: 1,
            rx_ts: u64::MAX,
        },
        Frame::Open {
            flow: 3,
            target: "1.1.1.1:53",
        },
        Frame::Close { flow: 3 },
        Frame::TooBig { mtu: 1391 },
        Frame::Stat(Stat {
            recv: 1000,
            lost: 7,
            jitter_us: 2400,
        }),
        Frame::Pad,
    ];
    for f in cases {
        let mut out = Vec::new();
        f.write(&mut out);
        assert_eq!(Frame::parse(&out), Some(f), "round trip of {f:?}");
    }
}

#[test]
fn stream_frames_round_trip() {
    let ranges = [
        AckRange {
            start: 4096,
            len: 1200,
        },
        AckRange {
            start: 8192,
            len: 300,
        },
        AckRange { start: 0, len: 0 },
        AckRange { start: 0, len: 0 },
    ];
    let cases: Vec<Frame> = vec![
        Frame::SOpen {
            sid: 1,
            kind: StreamKind::Tcp,
            target: "example.com:443",
        },
        Frame::SData {
            sid: 1,
            off: 0,
            payload: b"GET / HTTP/1.1\r\n",
        },
        Frame::SData {
            sid: u32::MAX,
            off: u64::MAX - 1,
            payload: b"x",
        },
        Frame::SAck {
            sid: 1,
            ack_to: 2048,
            ranges,
            nranges: 2,
        },
        Frame::SAck {
            sid: 1,
            ack_to: 0,
            ranges: [AckRange { start: 0, len: 0 }; SACK_RANGES],
            nranges: 0,
        },
        Frame::SFin {
            sid: 1,
            final_off: 123456,
        },
        Frame::SRst { sid: 1, code: 2 },
    ];
    for f in cases {
        let mut out = Vec::new();
        f.write(&mut out);
        assert_eq!(Frame::parse(&out), Some(f), "round trip of {f:?}");
    }
}

#[test]
fn a_sack_never_claims_more_ranges_than_it_carries() {
    let ranges = [AckRange { start: 1, len: 1 }; SACK_RANGES];
    let mut out = Vec::new();
    Frame::SAck {
        sid: 1,
        ack_to: 0,
        ranges,
        nranges: 99,
    }
    .write(&mut out);
    match Frame::parse(&out) {
        Some(Frame::SAck { nranges, .. }) => assert_eq!(nranges as usize, SACK_RANGES),
        other => panic!("expected a clamped SAck, got {other:?}"),
    }
    let mut lying = out.clone();
    lying[13] = SACK_RANGES as u8 + 1;
    assert_eq!(Frame::parse(&lying), None);
}

#[test]
fn truncated_and_unknown_frames_are_rejected_not_guessed() {
    assert_eq!(Frame::parse(&[]), None);
    assert_eq!(Frame::parse(&[0xfe]), None, "unknown type");
    assert_eq!(Frame::parse(&[T_DATA, 0]), None, "flow id cut in half");
    assert_eq!(
        Frame::parse(&[T_PING, 1, 2, 3]),
        None,
        "timestamp cut short"
    );
    assert_eq!(Frame::parse(&[T_STAT, 0, 0]), None);
    assert_eq!(
        Frame::parse(&[T_OPEN, 0, 0, 0xff, 0xfe]),
        None,
        "target is not utf-8"
    );
    assert_eq!(
        Frame::parse(&[T_SDATA, 0, 0, 0, 1, 0, 0]),
        None,
        "offset cut short"
    );
    assert_eq!(
        Frame::parse(&[T_SOPEN, 0, 0, 0, 1, 99]),
        None,
        "unknown stream kind"
    );
}

#[test]
fn handshake_datagrams_are_told_apart_by_their_first_eight_bytes() {
    let mut hs = Vec::new();
    handshake_datagram(HS_MSG1, b"noise", &mut hs);
    assert!(is_handshake(&hs));
    assert_eq!(parse_handshake(&hs), Some((HS_MSG1, &b"noise"[..])));

    let mut data = Vec::new();
    Head {
        cid: [1; 8],
        ctr: 0,
    }
    .write(&mut data);
    data.resize(OVERHEAD, 0);
    assert!(
        !is_handshake(&data),
        "a session datagram must never look like a handshake"
    );
    assert_eq!(parse_handshake(&data), None);
}

#[test]
fn mtu_arithmetic_leaves_room_for_every_header() {
    assert_eq!(payload_mtu(1426), 1426 - OVERHEAD - DATA_HDR);
    assert_eq!(payload_mtu(1426), 1391);
    assert_eq!(payload_mtu(1472), 1437);
    assert_eq!(stream_mtu(1426), 1381);
    assert_eq!(
        payload_mtu(10),
        0,
        "a carrier too small to use reports zero, not a panic"
    );
    assert_eq!(stream_mtu(10), 0);
}
