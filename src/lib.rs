pub mod carrier;
pub mod crypto;
pub mod handshake;
pub mod session;
pub mod stream;
pub mod wire;

pub use carrier::{Batch, Carrier};

pub const PROLOGUE: &[u8] = b"shabdiz-v1";

pub const KEEPALIVE_SECS: u64 = 15;
