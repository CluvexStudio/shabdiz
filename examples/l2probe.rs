#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use shabdiz::carrier::l2::{discover, Options, L2};
#[cfg(target_os = "linux")]
use shabdiz::carrier::{Batch, Carrier};

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("examples/l2probe.rs is a Linux-only raw-carrier probe");
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
#[cfg(target_os = "linux")]
async fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!(
            "usage: {} send|recv <peer-ip> <sport> <dport> [datagrams] [bytes] [batch] [mbit]",
            a[0]
        );
        std::process::exit(2);
    }
    let role = a[1].as_str();
    let peer: Ipv4Addr = a[2].parse()?;
    let sport: u16 = a[3].parse()?;
    let dport: u16 = a[4].parse()?;
    let count: usize = a.get(5).map_or(Ok(200_000), |s| s.parse())?;
    let size: usize = a.get(6).map_or(Ok(1200), |s| s.parse())?;
    let batch_n: usize = a.get(7).map_or(Ok(32), |s| s.parse())?;
    let mbit: f64 = a.get(8).map_or(Ok(0.0), |s| s.parse())?;

    let link = discover(peer)?;
    let l2 = L2::open(link, peer, sport, dport, Options::default())?;
    println!(
        "link: if#{} mtu {} src {} gw {:02x?} | carrier mtu {} | segmentation offload: {}",
        link.ifindex,
        link.mtu,
        link.src_ip,
        link.gateway_mac,
        l2.mtu(),
        if l2.offload() { "ON" } else { "off" }
    );
    if size > l2.mtu() {
        anyhow::bail!(
            "{size} bytes does not fit this carrier's {} byte datagram",
            l2.mtu()
        );
    }

    match role {
        "send" => send(&l2, count, size, batch_n, mbit).await,
        "recv" => recv(&l2, size, a.get(5).map_or(Ok(25), |s| s.parse())?).await,
        other => anyhow::bail!("unknown role {other}"),
    }
}

#[cfg(target_os = "linux")]
fn fill(buf: &mut [u8], n: u64) {
    buf[..8].copy_from_slice(&n.to_be_bytes());
    for (i, b) in buf.iter_mut().enumerate().skip(8) {
        *b = (i % 251) as u8;
    }
}

#[cfg(target_os = "linux")]
async fn send(l2: &L2, count: usize, size: usize, batch_n: usize, mbit: f64) -> anyhow::Result<()> {
    let mut batch = Batch::new(batch_n, size.max(1));
    let mut one = vec![0u8; size];
    let started = Instant::now();
    let mut sent = 0u64;
    let mut syscalls = 0u64;

    while (sent as usize) < count {
        batch.clear();
        while !batch.is_full() && (sent as usize) < count {
            fill(&mut one, sent);
            if !batch.push(&one) {
                break;
            }
            sent += 1;
        }
        l2.send_batch(&batch).await?;
        syscalls += 1;
        if mbit > 0.0 {
            let due = Duration::from_secs_f64(sent as f64 * size as f64 * 8.0 / (mbit * 1e6));
            if let Some(left) = due.checked_sub(started.elapsed()) {
                tokio::time::sleep(left).await;
            }
        }
    }
    let el = started.elapsed().max(Duration::from_micros(1));
    let bits = sent * size as u64 * 8;
    println!(
        "sent {sent} datagrams of {size} B in {:.2?} | {:.0} pkt/s | {:.1} Mbit/s | {syscalls} writes ({:.1} datagrams each)",
        el,
        sent as f64 / el.as_secs_f64(),
        bits as f64 / el.as_secs_f64() / 1e6,
        sent as f64 / syscalls as f64,
    );
    Ok(())
}

#[cfg(target_os = "linux")]
async fn recv(l2: &L2, size: usize, secs: u64) -> anyhow::Result<()> {
    let mut batch = Batch::new(64, size.max(64) + 64);
    let (mut got, mut bytes, mut highest, mut reads, mut coalesced) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut empty, mut acks) = (0u64, 0u64);
    let started = Instant::now();
    let deadline = started + Duration::from_secs(secs);
    let mut tick = started;
    let mut last_got = 0u64;
    println!("listening for {secs}s, reporting every 2s");

    while Instant::now() < deadline {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left.min(Duration::from_secs(2)), l2.recv_batch(&mut batch))
            .await
        {
            Err(_) => {}
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(0)) => empty += 1,
            Ok(Ok(n)) => {
                reads += 1;
                if n > 1 {
                    coalesced += 1;
                }
                for d in batch.iter() {
                    if d.len() >= 8 {
                        let seq = u64::from_be_bytes(d[..8].try_into().unwrap());
                        highest = highest.max(seq + 1);
                    }
                    got += 1;
                    bytes += d.len() as u64;
                }
                let mut ack = [0u8; 64];
                ack[..8].copy_from_slice(&highest.to_be_bytes());
                if l2.send(&ack).await.is_ok() {
                    acks += 1;
                }
            }
        }
        if tick.elapsed() >= Duration::from_secs(2) {
            let d = got - last_got;
            println!(
                "  +{:>2}s  {d:>6} datagrams ({:>6.1} Mbit/s)  total {got}, peer at {highest}, kernel drops {}",
                started.elapsed().as_secs(),
                d as f64 * size as f64 * 8.0 / 2.0 / 1e6,
                l2.kernel_drops(),
            );
            last_got = got;
            tick = Instant::now();
        }
    }

    let el = started.elapsed();
    let lost = highest.saturating_sub(got);
    println!(
        "received {got} datagrams / {:.1} MiB in {:.1?} | {:.0} pkt/s | {:.1} Mbit/s",
        bytes as f64 / 1_048_576.0,
        el,
        got as f64 / el.as_secs_f64(),
        bytes as f64 * 8.0 / el.as_secs_f64() / 1e6,
    );
    println!(
        "peer sent {highest} | lost {lost} ({:.2}%) | {reads} reads ({coalesced} coalesced, {:.1} datagrams each), {empty} empty, {acks} answers | kernel drops {}",
        if highest == 0 { 0.0 } else { lost as f64 * 100.0 / highest as f64 },
        if reads == 0 { 0.0 } else { got as f64 / reads as f64 },
        l2.kernel_drops(),
    );
    Ok(())
}
