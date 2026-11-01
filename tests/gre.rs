use shabdiz::carrier::gre;

fn received(frame: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[9] = 47;
    p.extend_from_slice(frame);
    p
}

#[test]
fn a_frame_round_trips() {
    let (a, b) = gre::macs(b"a token");
    let mut out = vec![0u8; gre::HDR + 64];
    let n = gre::frame(b, a, b"payload bytes", &mut out);
    assert_eq!(n, gre::HDR + 13);
    assert_eq!(
        gre::payload(&received(&out[..n]), b),
        Some(&b"payload bytes"[..])
    );
    assert_eq!(
        gre::payload(&received(&out[..n]), a),
        None,
        "not addressed to the sender"
    );
}

#[test]
fn the_header_is_the_shape_the_path_accepts() {
    let (a, b) = gre::macs(b"t");
    let mut out = vec![0u8; gre::HDR + 8];
    gre::frame(b, a, b"x", &mut out);
    assert_eq!(
        gre::HDR,
        18,
        "4 bytes of GRE plus a 14-byte Ethernet header"
    );
    assert_eq!(
        &out[..2],
        &[0x00, 0x00],
        "GRE version 0, no checksum, key or sequence"
    );
    assert_eq!(
        &out[2..4],
        &[0x65, 0x58],
        "transparent Ethernet bridging, NOT 0x0800"
    );
    assert_eq!(&out[4..10], &b[..], "destination MAC first");
    assert_eq!(&out[10..16], &a[..], "then the source");
    assert_eq!(
        &out[16..18],
        &[0x88, 0xb5],
        "a local-experimental ethertype: a dead end"
    );
}

#[test]
fn foreign_packets_are_rejected() {
    let (a, b) = gre::macs(b"token");
    let mut out = vec![0u8; gre::HDR + 8];
    let n = gre::frame(b, a, b"hello", &mut out);
    let good = received(&out[..n]);
    assert!(gre::payload(&good, b).is_some());

    let rejects = |tamper: &dyn Fn(&mut Vec<u8>)| -> bool {
        let mut p = good.clone();
        tamper(&mut p);
        gre::payload(&p, b).is_none()
    };
    assert!(rejects(&|p| p[20] = 0x20), "a key bit we never set");
    assert!(
        rejects(&|p| p[22..24].copy_from_slice(&[0x08, 0x00])),
        "IP over GRE"
    );
    assert!(
        rejects(&|p| p[36..38].copy_from_slice(&[0x08, 0x00])),
        "IP inside the bridge"
    );
    assert!(rejects(&|p| p[24] ^= 1), "another session's address");
    assert_eq!(
        gre::payload(&good[..20 + gre::HDR], b),
        None,
        "a header with no payload"
    );
    assert_eq!(gre::payload(&[], b), None, "an empty packet");

    let mut opts = vec![0u8; 24];
    opts[0] = 0x46;
    opts[9] = 47;
    opts.extend_from_slice(&out[..n]);
    assert_eq!(gre::payload(&opts, b), Some(&b"hello"[..]));
}

#[test]
fn the_two_addresses_are_legal_unicast_and_token_bound() {
    let (a, b) = gre::macs(b"one token");
    let (c, d) = gre::macs(b"another token");
    assert_ne!(
        a, b,
        "the two ends must differ or each would accept its own frames"
    );
    assert_ne!(a, c, "a different token gives a different address");
    assert_ne!(b, d);
    assert_eq!(
        gre::macs(b"one token"),
        (a, b),
        "derivation is deterministic"
    );
    for m in [a, b, c, d] {
        assert_eq!(
            m[0] & 0x01,
            0,
            "unicast: the low bit of the first octet is clear"
        );
        assert_eq!(m[0] & 0x02, 0x02, "locally administered: no vendor owns it");
    }
}

#[test]
fn the_mtu_leaves_room_for_every_header() {
    assert_eq!(
        gre::path_mtu(1500),
        1462,
        "1500 less the outer IP header and ours"
    );
    assert_eq!(
        gre::path_mtu(1500) + 20 + gre::HDR,
        1500,
        "and not a byte wasted"
    );
    assert_eq!(
        gre::path_mtu(10),
        0,
        "a nonsense path MTU must not wrap around"
    );
}

#[test]
fn icmp_errors_are_survivable_and_real_ones_are_not() {
    let e = |n| std::io::Error::from_raw_os_error(n);
    for n in [
        libc::ENOPROTOOPT,
        libc::EHOSTUNREACH,
        libc::ENETUNREACH,
        libc::ECONNREFUSED,
    ] {
        assert!(
            gre::is_path_error(&e(n)),
            "errno {n} is the path, not the socket"
        );
    }
    assert!(
        !gre::is_path_error(&e(libc::EMSGSIZE)),
        "the datagram really was too big"
    );
    assert!(
        !gre::is_path_error(&e(libc::EPERM)),
        "no CAP_NET_RAW must not look transient"
    );
    assert!(
        !gre::is_path_error(&e(libc::EBADF)),
        "a broken socket is broken"
    );
    assert!(!gre::is_path_error(&std::io::Error::other(
        "no errno at all"
    )));
}
