use shabdiz::crypto::{Jitter, Keys, Rx, REPLAY_WINDOW};
use shabdiz::wire::{Frame, Head, HEAD, OVERHEAD};

fn pair() -> (Keys, Keys) {
    let i2r = [7u8; 32];
    let r2i = [9u8; 32];
    (
        Keys::new([1, 2, 3, 4, 5, 6, 7, 8], i2r, r2i, true),
        Keys::new([1, 2, 3, 4, 5, 6, 7, 8], i2r, r2i, false),
    )
}

#[test]
fn a_sealed_datagram_opens_on_the_other_side() {
    let (dialer, peer) = pair();
    let mut inner = Vec::new();
    Frame::Data {
        flow: 0,
        payload: b"one udp datagram",
    }
    .write(&mut inner);

    let mut dg = Vec::new();
    let ctr = dialer.seal(&inner, &mut dg);
    assert_eq!(
        ctr, 1,
        "counters start at one so that zero means nothing arrived"
    );
    assert_eq!(dg.len(), inner.len() + OVERHEAD);

    let (got_ctr, len) = peer
        .open(&mut dg)
        .expect("peer opens what the dialler sealed");
    assert_eq!(got_ctr, 1);
    assert_eq!(
        Frame::parse(Keys::inner(&dg, len)),
        Some(Frame::Data {
            flow: 0,
            payload: b"one udp datagram"
        })
    );
}

#[test]
fn each_direction_has_its_own_key() {
    let (dialer, peer) = pair();
    let mut dg = Vec::new();
    dialer.seal(b"\x01\x00\x00hello", &mut dg);
    assert!(dialer.open(&mut dg.clone()).is_none());
    assert!(peer.open(&mut dg).is_some());
}

#[test]
fn counters_advance_once_per_datagram() {
    let (dialer, _) = pair();
    let mut dg = Vec::new();
    for want in 1..=5u64 {
        assert_eq!(dialer.seal(b"\x08", &mut dg), want);
    }
}

#[test]
fn a_tampered_datagram_is_dropped_everywhere_it_can_be_touched() {
    let (dialer, peer) = pair();
    let mut good = Vec::new();
    dialer.seal(b"\x01\x00\x00payload", &mut good);

    for (what, at) in [
        ("cid", 0usize),
        ("counter", 10),
        ("ciphertext", HEAD + 2),
        ("tag", good.len() - 1),
    ] {
        let mut bad = good.clone();
        bad[at] ^= 0x80;
        assert!(
            peer.open(&mut bad).is_none(),
            "a flipped bit in the {what} must not open"
        );
    }
    let mut truncated = good.clone();
    truncated.truncate(OVERHEAD - 1);
    assert!(peer.open(&mut truncated).is_none());
}

#[test]
fn a_datagram_for_another_session_is_not_opened() {
    let (dialer, _) = pair();
    let other = Keys::new([9; 8], [7u8; 32], [9u8; 32], false);
    let mut dg = Vec::new();
    dialer.seal(b"\x08", &mut dg);
    assert!(
        other.open(&mut dg).is_none(),
        "the cid is authenticated, not decorative"
    );
    assert_eq!(Head::parse(&dg).unwrap().cid, [1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn the_replay_window_accepts_each_counter_once() {
    let mut rx = Rx::new();
    assert!(!rx.accept(0), "zero is not a valid counter");
    assert!(rx.accept(1));
    assert!(!rx.accept(1), "a replay is refused");
    assert_eq!(rx.duplicates, 1);
    assert!(rx.accept(2));
    assert_eq!(rx.accepted, 2);
    assert_eq!(rx.lost(), 0);
}

#[test]
fn reordering_inside_the_window_is_accepted_and_counted() {
    let mut rx = Rx::new();
    for c in [1u64, 2, 5, 3, 4] {
        assert!(rx.accept(c), "counter {c}");
    }
    assert_eq!(rx.accepted, 5);
    assert_eq!(rx.reordered, 2, "3 and 4 arrived after 5");
    assert_eq!(rx.lost(), 0, "nothing was actually lost");
}

#[test]
fn loss_is_exact_and_needs_no_probe_traffic() {
    let mut rx = Rx::new();
    for c in [1u64, 2, 4, 5, 6, 8, 9, 10] {
        assert!(rx.accept(c));
    }
    assert_eq!(rx.highest(), 10);
    assert_eq!(rx.accepted, 8);
    assert_eq!(rx.lost(), 2);
    assert!((rx.loss_ratio() - 0.2).abs() < 1e-9);
}

#[test]
fn a_counter_older_than_the_window_is_refused_rather_than_trusted() {
    let mut rx = Rx::new();
    assert!(rx.accept(1));
    assert!(rx.accept(REPLAY_WINDOW + 100));
    assert!(!rx.accept(2), "far outside the window");
    assert_eq!(rx.too_old, 1);
    assert!(rx.accept(REPLAY_WINDOW + 99));
}

#[test]
fn a_jump_larger_than_the_window_clears_it_without_losing_the_new_counter() {
    let mut rx = Rx::new();
    assert!(rx.accept(1));
    assert!(rx.accept(10_000));
    assert!(
        !rx.accept(10_000),
        "the new highest is remembered as received"
    );
    assert_eq!(rx.accepted, 2);
}

#[test]
fn jitter_ignores_the_clock_offset_and_measures_only_its_variation() {
    let offset = 3_600_000_000i64;
    let mut j = Jitter::new();
    for i in 0..50i64 {
        let tx = i * 10_000;
        j.sample(tx, tx + offset);
    }
    assert_eq!(
        j.micros(),
        0,
        "a steady path has no jitter however wrong the clocks are"
    );

    let mut j = Jitter::new();
    for i in 0..200i64 {
        let tx = i * 10_000;
        let wobble = if i % 2 == 0 { 20_000 } else { -20_000 };
        j.sample(tx, tx + offset + wobble);
    }
    assert!(
        j.micros() > 10_000,
        "a wobbling path shows jitter, got {} us",
        j.micros()
    );
}
