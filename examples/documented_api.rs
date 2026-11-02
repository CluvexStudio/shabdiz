use std::sync::Arc;

#[allow(dead_code)]
async fn the_documented_api(
    local_key: [u8; 32],
    peer_key: [u8; 32],
    psk: [u8; 32],
    flow: u16,
) -> anyhow::Result<()> {
    let carrier = Arc::new(shabdiz::carrier::udp::Udp::bind("0.0.0.0:7000".parse()?).await?);
    let accepted = shabdiz::handshake::accept(&*carrier, &local_key, &peer_key, &psk).await?;
    let session = shabdiz::session::start(
        carrier,
        accepted.keys,
        accepted.params,
        shabdiz::session::Role::Responder,
        shabdiz::session::Config::default(),
        Some(shabdiz::session::Handshake { first: accepted.first, reply: accepted.reply }),
    );

    session.send(flow, b"a datagram");
    let (_flow, _bytes) = session.recv().await.unwrap();
    Ok(())
}

fn main() {}
