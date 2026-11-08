use shabdiz::carrier::tagged;

const IPIP: &str = "shabdiz-ipip-tags-v1";
const SIT: &str = "shabdiz-6to4-tags-v1";

fn received(frame: &[u8], proto: u8) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[9] = proto;
    p.extend_from_slice(frame);
    p
}

#[test]
fn a_packet_round_trips_to_the_end_it_is_addressed_to() {
    let (a, b) = tagged::tags(b"a token", IPIP);
    let mut out = vec![0u8; tagged::HDR + 64];
    let n = tagged::frame(b, 1, b"payload bytes", &mut out);
    assert_eq!(n, tagged::HDR + 13);
    assert_eq!(
        tagged::payload(&received(&out[..n], 4), b),
        Some(&b"payload bytes"[..])
    );
    assert_eq!(
        tagged::payload(&received(&out[..n], 4), a),
        None,
        "a packet addressed to one end must not open at the other"
    );
}

#[test]
fn the_payload_never_begins_with_something_a_filter_reads_as_ip() {
    for token in [b"t".as_slice(), b"another token", b""] {
        for ctx in [IPIP, SIT] {
            let (a, b) = tagged::tags(token, ctx);
            for tag in [a, b] {
                let version = (tag >> 28) as u8;
                assert_ne!(
                    version, 4,
                    "a tag starting with 4 reads as an IPv4 header, which is the shape measured \
                     to be dropped"
                );
                assert_ne!(
                    version, 6,
                    "a tag starting with 6 reads as an IPv6 header, which is the shape measured \
                     to be dropped"
                );
            }
        }
    }
}

#[test]
fn the_two_ends_get_different_tags_and_the_same_pair_from_the_same_token() {
    let (a, b) = tagged::tags(b"shared token", IPIP);
    assert_ne!(
        a, b,
        "both ends writing the same tag would read their own traffic"
    );
    assert_eq!((a, b), tagged::tags(b"shared token", IPIP));
    assert_ne!(
        (a, b),
        tagged::tags(b"other token", IPIP),
        "a different token has to give a different pair"
    );
    assert_ne!(
        tagged::tags(b"shared token", IPIP),
        tagged::tags(b"shared token", SIT),
        "ipip and 6to4 must not collide when both run on one token"
    );
}

#[test]
fn a_short_or_foreign_packet_is_refused_rather_than_read_past_its_end() {
    let (_, b) = tagged::tags(b"t", IPIP);
    assert_eq!(tagged::payload(&[], b), None);
    assert_eq!(tagged::payload(&received(&[], 4), b), None);
    assert_eq!(tagged::payload(&received(&[0u8; 4], 4), b), None);
    assert_eq!(
        tagged::payload(&received(&[0u8; tagged::HDR], 4), b),
        None,
        "a header with no payload carries nothing"
    );
}

#[test]
fn an_options_bearing_ip_header_is_skipped_by_its_own_length() {
    let (_, b) = tagged::tags(b"t", IPIP);
    let mut out = vec![0u8; tagged::HDR + 32];
    let n = tagged::frame(b, 7, b"hello", &mut out);
    let mut p = vec![0u8; 24];
    p[0] = 0x46;
    p[9] = 4;
    p.extend_from_slice(&out[..n]);
    assert_eq!(tagged::payload(&p, b), Some(&b"hello"[..]));
}

#[test]
fn the_mtu_leaves_room_for_the_ip_and_tag_headers() {
    assert_eq!(tagged::path_mtu(1500), 1500 - 20 - tagged::HDR);
    assert_eq!(tagged::path_mtu(10), 0, "a tiny path cannot carry anything");
}
