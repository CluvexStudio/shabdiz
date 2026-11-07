use shabdiz::carrier::esp;

fn received(frame: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[9] = 50;
    p.extend_from_slice(frame);
    p
}

#[test]
fn a_packet_round_trips() {
    let (a, b) = esp::spis(b"a token");
    let mut out = vec![0u8; esp::HDR + 64];
    let n = esp::frame(b, 1, b"payload bytes", &mut out);
    assert_eq!(n, esp::HDR + 13);
    assert_eq!(
        esp::payload(&received(&out[..n]), b),
        Some(&b"payload bytes"[..])
    );
    assert_eq!(
        esp::payload(&received(&out[..n]), a),
        None,
        "not addressed to the sender"
    );
}

#[test]
fn the_header_is_the_shape_a_filter_expects_of_esp() {
    let (_, b) = esp::spis(b"t");
    let mut out = vec![0u8; esp::HDR + 8];
    esp::frame(b, 0x11223344, b"x", &mut out);
    assert_eq!(esp::HDR, 8, "RFC 4303: a 4-byte SPI then a 4-byte sequence");
    assert_eq!(
        &out[..4],
        &b.to_be_bytes(),
        "the SPI is the receiver's, big endian, as on the wire"
    );
    assert_eq!(
        &out[4..8],
        &[0x11, 0x22, 0x33, 0x44],
        "then the sequence number"
    );
    assert_eq!(
        &out[8..9],
        b"x",
        "and the payload, already sealed by shabdiz"
    );
}

#[test]
fn the_sequence_number_is_written_where_esp_keeps_it() {
    let (_, b) = esp::spis(b"t");
    let mut first = vec![0u8; esp::HDR + 4];
    let mut second = vec![0u8; esp::HDR + 4];
    esp::frame(b, 7, b"x", &mut first);
    esp::frame(b, 8, b"x", &mut second);
    assert_eq!(
        u32::from_be_bytes(first[4..8].try_into().unwrap()),
        7,
        "the sequence number is the second word, big endian"
    );
    assert_ne!(
        &first[4..8],
        &second[4..8],
        "a constant sequence number is a giveaway a real ESP flow never has"
    );
    assert_eq!(
        &first[..4],
        &second[..4],
        "while the SPI stays the same for the session"
    );
}

#[test]
fn foreign_packets_are_rejected() {
    let (a, b) = esp::spis(b"token");
    let mut out = vec![0u8; esp::HDR + 8];
    let n = esp::frame(b, 1, b"hello", &mut out);
    let good = received(&out[..n]);
    assert!(esp::payload(&good, b).is_some());

    let rejects = |tamper: &dyn Fn(&mut Vec<u8>)| -> bool {
        let mut p = good.clone();
        tamper(&mut p);
        esp::payload(&p, b).is_none()
    };
    assert!(rejects(&|p| p[20] ^= 1), "another session's SPI");
    assert!(rejects(&|p| p[23] ^= 0xff), "and the low byte of it too");
    assert_eq!(
        esp::payload(&good[..20 + esp::HDR], b),
        None,
        "a header with no payload"
    );
    assert_eq!(esp::payload(&[], b), None, "an empty packet");
    assert_eq!(
        esp::payload(&received(&out[..4]), b),
        None,
        "a truncated header"
    );

    let mut opts = vec![0u8; 24];
    opts[0] = 0x46;
    opts[9] = 50;
    opts.extend_from_slice(&out[..n]);
    assert_eq!(
        esp::payload(&opts, b),
        Some(&b"hello"[..]),
        "an IP header carrying options is still parsed"
    );
    assert_ne!(
        esp::payload(&good, b),
        esp::payload(&good, a),
        "each end only accepts its own SPI"
    );
}

#[test]
fn the_two_spis_differ_and_follow_the_token() {
    let (a, b) = esp::spis(b"one token");
    let (c, d) = esp::spis(b"another token");
    assert_ne!(
        a, b,
        "each end needs its own or both accept their own packets"
    );
    assert_ne!(a, c, "a different token gives a different SPI");
    assert_ne!(b, d);
    assert_eq!(
        esp::spis(b"one token"),
        (a, b),
        "derivation is deterministic"
    );
    for spi in [a, b, c, d] {
        assert!(
            spi >= 0x1000_0000,
            "0 to 255 are reserved by RFC 4303, and a tiny SPI looks synthetic: {spi:#x}"
        );
    }
}

#[test]
fn the_mtu_leaves_room_for_every_header() {
    assert_eq!(
        esp::path_mtu(1500),
        1472,
        "1500 less the outer IP header and the ESP header"
    );
    assert_eq!(
        esp::path_mtu(1500) + 20 + esp::HDR,
        1500,
        "and not a byte wasted"
    );
    assert_eq!(
        esp::path_mtu(10),
        0,
        "a nonsense path MTU must not wrap around"
    );
    assert!(
        esp::path_mtu(1500) > shabdiz::carrier::gre::path_mtu(1500),
        "ESP's header is smaller than GRE's, so it carries more"
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
            esp::is_path_error(&e(n)),
            "errno {n} is the path, not the socket"
        );
    }
    assert!(!esp::is_path_error(&e(libc::EMSGSIZE)));
    assert!(!esp::is_path_error(&e(libc::EPERM)));
    assert!(!esp::is_path_error(&e(libc::EBADF)));
}
