use log::trace;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, UdpSocket};

use crate::crypto::Sealed;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ClientMessage {
    Hello,
    MatchRequest {
        pubkey: Vec<u8>,
        enc_matching_key: Sealed<Vec<u8>>,
    },

    #[cfg(feature = "debugging")]
    Initialize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ServerMessage {
    ServerPubKey {
        pubkey: Vec<u8>,
    },
    Matched {
        enc_your_addr: Sealed<SocketAddr>,
        enc_peer_addr: Sealed<SocketAddr>,
    },
}

pub fn send_to<T: Serialize>(v: T, sock: &UdpSocket, to: SocketAddr) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(&v).unwrap();
    trace!(
        "sending: {}",
        std::str::from_utf8(&bytes).expect("UTF-8 JSON")
    );
    let _ = sock.send_to(&bytes, to)?;
    Ok(())
}

pub fn recv_from<T: serde::de::DeserializeOwned>(
    sock: &UdpSocket,
) -> std::io::Result<(T, SocketAddr)> {
    let mut buf = [0; 4096];
    let (sz, src) = sock.recv_from(&mut buf)?;
    trace!("src={}", src);
    let msg: T = serde_json::from_slice(&buf[..sz])?;
    Ok((msg, src))
}
