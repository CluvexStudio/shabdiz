use std::time::{Duration, Instant};

use shabdiz::stream::{State, Stream, MAX_INFLIGHT, MAX_REASSEMBLY, MIN_RTO};
use shabdiz::wire::{Frame, StreamKind};

const MSS: usize = 1200;

fn stream(sid: u32) -> Stream {
    Stream::new(sid, StreamKind::Tcp)
}

fn deliver(frames: &[Vec<u8>], to: &mut Stream, now: Instant) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut got = Vec::new();
    let mut back = Vec::new();
    for f in frames {
        match Frame::parse(f).expect("a frame the engine wrote must parse") {
            Frame::SData { off, payload, .. } => {
                got.extend_from_slice(&to.on_data(off, payload, &mut back))
            }
            Frame::SAck {
                ack_to,
                ranges,
                nranges,
                ..
            } => to.on_ack(ack_to, &ranges, nranges, now, &mut back),
            Frame::SFin { final_off, .. } => to.on_fin(final_off, &mut back),
            Frame::SRst { .. } => to.on_reset(),
            other => panic!("a stream never writes {other:?}"),
        }
    }
    (got, back)
}

#[test]
fn a_clean_transfer_delivers_every_byte_in_order() {
    let t0 = Instant::now();
    let (mut a, mut b) = (stream(1), stream(1));
    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();

    let mut frames = Vec::new();
    let took = a.write(&payload, MSS, t0, &mut frames);
    assert_eq!(took, payload.len());
    assert!(frames.len() >= payload.len() / MSS);

    let (got, acks) = deliver(&frames, &mut b, t0);
    assert_eq!(got, payload, "every byte, in order");

    deliver(&acks, &mut a, t0 + Duration::from_millis(90));
    assert_eq!(a.inflight(), 0, "acknowledged data is no longer held");
}

#[test]
fn a_gap_is_held_until_it_fills_then_released_at_once() {
    let t0 = Instant::now();
    let (mut a, mut b) = (stream(1), stream(1));
    let payload: Vec<u8> = (0..MSS as u32 * 3).map(|i| i as u8).collect();
    let mut frames = Vec::new();
    a.write(&payload, MSS, t0, &mut frames);
    assert_eq!(frames.len(), 3);

    let (got, _) = deliver(&[frames[0].clone()], &mut b, t0);
    assert_eq!(
        got.len(),
        MSS,
        "the first segment is in order and goes straight through"
    );
    let (got, _) = deliver(&[frames[2].clone()], &mut b, t0);
    assert!(got.is_empty(), "the third must wait for the second");
    let (got, _) = deliver(&[frames[1].clone()], &mut b, t0);
    assert_eq!(got.len(), MSS * 2, "filling the gap releases both at once");
}

#[test]
fn a_lost_segment_goes_again_when_the_timer_fires() {
    let t0 = Instant::now();
    let (mut a, mut b) = (stream(1), stream(1));
    let payload = vec![7u8; MSS * 2];
    let mut frames = Vec::new();
    a.write(&payload, MSS, t0, &mut frames);

    let (got, acks) = deliver(&frames[1..], &mut b, t0);
    assert!(got.is_empty());
    deliver(&acks, &mut a, t0);

    let mut out = Vec::new();
    a.tick(t0 + MIN_RTO / 2, &mut out);
    assert!(out.is_empty(), "the timer has not fired yet");

    a.tick(t0 + MIN_RTO + Duration::from_millis(1), &mut out);
    assert_eq!(
        out.len(),
        1,
        "exactly the lost segment, and only one of them"
    );
    let (got, _) = deliver(&out, &mut b, t0);
    assert_eq!(got.len(), MSS * 2, "the retransmit completes the stream");
}

#[test]
fn an_ack_that_overtakes_a_segment_resends_it_without_waiting() {
    let t0 = Instant::now();
    let (mut a, mut b) = (stream(1), stream(1));
    let payload = vec![3u8; MSS * 4];
    let mut frames = Vec::new();
    a.write(&payload, MSS, t0, &mut frames);

    let (_, acks) = deliver(&frames[1..], &mut b, t0);

    let later = t0 + Duration::from_millis(60);
    let mut out = Vec::new();
    for ack in &acks {
        if let Frame::SAck {
            ack_to,
            ranges,
            nranges,
            ..
        } = Frame::parse(ack).unwrap()
        {
            a.on_ack(ack_to, &ranges, nranges, later, &mut out);
        }
    }
    assert!(
        !out.is_empty(),
        "the gap is resent on the acknowledgement, not on the timer"
    );
    let (got, _) = deliver(&out, &mut b, later);
    assert_eq!(got.len(), MSS * 4, "and that completes the stream");
}

#[test]
fn the_acknowledgement_reports_the_gaps_being_held() {
    let t0 = Instant::now();
    let (mut a, mut b) = (stream(9), stream(9));
    let payload = vec![1u8; MSS * 4];
    let mut frames = Vec::new();
    a.write(&payload, MSS, t0, &mut frames);

    deliver(&[frames[1].clone(), frames[3].clone()], &mut b, t0);
    match Frame::parse(&b.ack_frame()).unwrap() {
        Frame::SAck {
            sid,
            ack_to,
            ranges,
            nranges,
        } => {
            assert_eq!(sid, 9);
            assert_eq!(ack_to, 0, "nothing is in order yet");
            assert_eq!(nranges, 2, "two separate runs are being held");
            assert_eq!(ranges[0].start, MSS as u64);
            assert_eq!(ranges[0].len as usize, MSS);
            assert_eq!(ranges[1].start, MSS as u64 * 3);
        }
        other => panic!("expected an SAck, got {other:?}"),
    }
}

#[test]
fn a_full_window_stops_taking_writes_until_an_ack_makes_room() {
    let t0 = Instant::now();
    let mut a = stream(1);
    let big = vec![0u8; MAX_INFLIGHT + MSS * 4];
    let mut frames = Vec::new();
    let took = a.write(&big, MSS, t0, &mut frames);
    assert_eq!(
        took, MAX_INFLIGHT,
        "it takes exactly the window and no more"
    );
    assert_eq!(a.writable(), 0);

    let mut more = Vec::new();
    assert_eq!(
        a.write(&big, MSS, t0, &mut more),
        0,
        "and nothing while it is full"
    );
    assert!(more.is_empty());

    let mut out = Vec::new();
    a.on_ack(
        MSS as u64 * 10,
        &[],
        0,
        t0 + Duration::from_millis(90),
        &mut out,
    );
    assert_eq!(a.writable(), MSS * 10);
}

#[test]
fn data_already_delivered_is_acknowledged_again_not_delivered_twice() {
    let t0 = Instant::now();
    let (mut a, mut b) = (stream(1), stream(1));
    let mut frames = Vec::new();
    a.write(&vec![5u8; MSS], MSS, t0, &mut frames);

    let (first, _) = deliver(&frames, &mut b, t0);
    assert_eq!(first.len(), MSS);
    let (again, acks) = deliver(&frames, &mut b, t0);
    assert!(
        again.is_empty(),
        "a duplicate is not delivered a second time"
    );
    assert!(
        !acks.is_empty(),
        "but it is acknowledged, since the last ack clearly went missing"
    );
}

#[test]
fn an_overlapping_retransmit_contributes_only_its_new_bytes() {
    let mut b = stream(1);
    let mut out = Vec::new();
    let first = vec![1u8; 1200];
    assert_eq!(b.on_data(0, &first, &mut out).len(), 1200);
    let overlap = vec![2u8; 1200];
    let got = b.on_data(600, &overlap, &mut out);
    assert_eq!(got.len(), 600, "only the part past what we had");
    assert_eq!(got, vec![2u8; 600]);
}

#[test]
fn reassembly_past_the_budget_is_dropped_and_deliberately_not_acknowledged() {
    let mut b = stream(1);
    let mut out = Vec::new();
    let seg = vec![0u8; MSS];

    let mut off = MSS as u64;
    let mut pushed = 0usize;
    while pushed < MAX_REASSEMBLY + MSS * 4 {
        b.on_data(off, &seg, &mut out);
        off += MSS as u64;
        pushed += MSS;
    }

    let acked: u64 = match Frame::parse(&b.ack_frame()).unwrap() {
        Frame::SAck {
            ranges, nranges, ..
        } => ranges[..nranges as usize]
            .iter()
            .map(|r| r.len as u64)
            .sum(),
        other => panic!("expected an SAck, got {other:?}"),
    };
    assert!(
        acked <= MAX_REASSEMBLY as u64,
        "acknowledged {acked} bytes but only {MAX_REASSEMBLY} can be held"
    );
}

#[test]
fn a_loss_on_one_stream_does_not_hold_up_another() {
    let t0 = Instant::now();
    let (mut a1, mut b1) = (stream(1), stream(1));
    let (mut a2, mut b2) = (stream(2), stream(2));

    let mut f1 = Vec::new();
    a1.write(&vec![1u8; MSS * 3], MSS, t0, &mut f1);
    let mut f2 = Vec::new();
    a2.write(&vec![2u8; MSS * 3], MSS, t0, &mut f2);

    let (got1, _) = deliver(&f1[1..], &mut b1, t0);
    let (got2, _) = deliver(&f2, &mut b2, t0);

    assert!(got1.is_empty(), "stream 1 is stalled, as it must be");
    assert_eq!(
        got2.len(),
        MSS * 3,
        "stream 2 is untouched by stream 1's loss"
    );
    assert_eq!(b2.state(), State::Open);
}

#[test]
fn finish_is_only_final_once_every_byte_before_it_has_arrived() {
    let t0 = Instant::now();
    let (mut a, mut b) = (stream(1), stream(1));
    let mut frames = Vec::new();
    a.write(&vec![4u8; MSS * 2], MSS, t0, &mut frames);
    a.finish(&mut frames);

    let fin = frames.pop().expect("finish frame");
    deliver(&[fin], &mut b, t0);
    assert_eq!(
        b.state(),
        State::Open,
        "a gap before the end is still a gap"
    );

    deliver(&frames, &mut b, t0);
    assert_eq!(
        b.state(),
        State::PeerFinished,
        "and now it is really the end"
    );
}

#[test]
fn a_reset_kills_the_stream_at_both_ends() {
    let t0 = Instant::now();
    let (mut a, mut b) = (stream(1), stream(1));
    let mut frames = Vec::new();
    a.write(&vec![0u8; MSS], MSS, t0, &mut frames);
    let mut rst = Vec::new();
    a.reset(1, &mut rst);
    assert_eq!(a.state(), State::Dead);
    assert_eq!(a.inflight(), 0);

    deliver(&rst, &mut b, t0);
    assert_eq!(b.state(), State::Dead);
    let mut out = Vec::new();
    assert_eq!(
        b.on_data(0, &[1, 2, 3], &mut out).len(),
        0,
        "a dead stream takes nothing"
    );
}

#[test]
fn the_timer_backs_off_and_eventually_gives_up() {
    let t0 = Instant::now();
    let mut a = stream(1);
    let mut frames = Vec::new();
    a.write(&vec![0u8; MSS], MSS, t0, &mut frames);

    let mut at = t0;
    let mut rtos = Vec::new();
    for _ in 0..6 {
        at += a.rto() + Duration::from_millis(1);
        let mut out = Vec::new();
        a.tick(at, &mut out);
        rtos.push(a.rto());
    }
    assert!(
        rtos.windows(2).all(|w| w[1] >= w[0]),
        "each timeout waits at least as long as the last: {rtos:?}"
    );
    assert!(
        rtos.last().unwrap() > &MIN_RTO,
        "and it has actually backed off"
    );

    for _ in 0..24 {
        at += a.rto() + Duration::from_millis(1);
        let mut out = Vec::new();
        a.tick(at, &mut out);
    }
    assert_eq!(a.state(), State::Dead);
}
