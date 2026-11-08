#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use shabdiz::carrier::gre;
#[cfg(target_os = "linux")]
use shabdiz::carrier::{Batch, Carrier};

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("examples/greprobe.rs is a Linux-only raw-carrier probe");
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
#[cfg(target_os = "linux")]
async fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 {
        eprintln!("usage: {} send|recv <peer-ip> <token> [...]", a[0]);
        std::process::exit(2);
    }
    let role = a[1].as_str();
    let peer: Ipv4Addr = a[2].parse()?;
    let (entry_mac, exit_mac) = gre::macs(a[3].as_bytes());
    let (local, remote) = match role {
        "send" => (entry_mac, exit_mac),
        "recv" => (exit_mac, entry_mac),
        other => anyhow::bail!("unknown role {other}"),
    };

    let size: usize = a.get(5).map_or(Ok(1400), |s| s.parse())?;
    let mtu = gre::path_mtu(1500);
    let gre = gre::open(peer, local, remote, mtu)?;
    println!(
        "gre to {peer} on IP protocol 47 | carrier mtu {mtu} | local {local:02x?} -> {remote:02x?} | \
         up to {} datagrams per syscall",
        gre.batch_size()
    );
    if size > mtu {
        anyhow::bail!("{size} bytes does not fit this carrier's {mtu} byte datagram");
    }

    match role {
        "send" => {
            let count: usize = a.get(4).map_or(Ok(200_000), |s| s.parse())?;
            let batch_n: usize = a.get(6).map_or(Ok(32), |s| s.parse())?;
            let mbit: f64 = a.get(7).map_or(Ok(0.0), |s| s.parse())?;
            send(&gre, count, size, batch_n, mbit).await
        }
        _ => recv(&gre, size, a.get(4).map_or(Ok(25), |s| s.parse())?).await,
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
async fn send(
    gre: &gre::Gre,
    count: usize,
    size: usize,
    batch_n: usize,
    mbit: f64,
) -> anyhow::Result<()> {
    let mut batch = Batch::new(batch_n, size.max(1));
    let mut one = vec![0u8; size];
    let started = Instant::now();
    let (mut sent, mut syscalls) = (0u64, 0u64);

    while (sent as usize) < count {
        batch.clear();
        while !batch.is_full() && (sent as usize) < count {
            fill(&mut one, sent);
            if !batch.push(&one) {
                break;
            }
            sent += 1;
        }
        gre.send_batch(&batch).await?;
        syscalls += 1;
        if mbit > 0.0 {
            let due = Duration::from_secs_f64(sent as f64 * size as f64 * 8.0 / (mbit * 1e6));
            if let Some(left) = due.checked_sub(started.elapsed()) {
                tokio::time::sleep(left).await;
            }
        }
    }
    let el = started.elapsed().max(Duration::from_micros(1));
    println!(
        "sent {sent} datagrams of {size} B in {:.2?} | {:.0} pkt/s | {:.1} Mbit/s offered | \
         {syscalls} writes ({:.1} datagrams each)",
        el,
        sent as f64 / el.as_secs_f64(),
        sent as f64 * size as f64 * 8.0 / el.as_secs_f64() / 1e6,
        sent as f64 / syscalls as f64,
    );
    Ok(())
}

#[cfg(target_os = "linux")]
async fn recv(gre: &gre::Gre, size: usize, secs: u64) -> anyhow::Result<()> {
    let mut batch = Batch::new(64, size.max(64) + 64);
    let (mut got, mut bytes, mut highest, mut reads, mut empty) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let started = Instant::now();
    let deadline = started + Duration::from_secs(secs);
    let (mut tick, mut last) = (started, 0u64);
    println!("listening for {secs}s, reporting every 2s");

    while Instant::now() < deadline {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left.min(Duration::from_secs(2)), gre.recv_batch(&mut batch))
            .await
        {
            Err(_) => {}
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(0)) => empty += 1,
            Ok(Ok(_)) => {
                reads += 1;
                for d in batch.iter() {
                    if d.len() >= 8 {
                        highest = highest.max(u64::from_be_bytes(d[..8].try_into().unwrap()) + 1);
                    }
                    got += 1;
                    bytes += d.len() as u64;
                }
                let mut ack = [0u8; 64];
                ack[..8].copy_from_slice(&highest.to_be_bytes());
                let _ = gre.send(&ack).await;
            }
        }
        if tick.elapsed() >= Duration::from_secs(2) {
            println!(
                "  +{:>2}s  {:>7} datagrams ({:>6.1} Mbit/s)  total {got}, peer at {highest}, \
                 foreign {}, icmp {}",
                started.elapsed().as_secs(),
                got - last,
                (got - last) as f64 * size as f64 * 8.0 / 2.0 / 1e6,
                gre.foreign(),
                gre.icmp_errors(),
            );
            last = got;
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
        "peer sent {highest} | lost {lost} ({:.2}%) | {reads} reads ({:.1} datagrams each), \
         {empty} empty | foreign {} | ICMP errors survived {}",
        if highest == 0 {
            0.0
        } else {
            lost as f64 * 100.0 / highest as f64
        },
        if reads == 0 {
            0.0
        } else {
            got as f64 / reads as f64
        },
        gre.foreign(),
        gre.icmp_errors(),
    );
    Ok(())
}
