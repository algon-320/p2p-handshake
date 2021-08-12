use log::trace;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, UdpSocket};

use crate::{crypto::Sealed, error::Result};

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

pub fn send_to<T: Serialize>(v: T, sock: &UdpSocket, to: SocketAddr) -> Result<()> {
    let bytes = serde_cbor::to_vec(&v)?;
    trace!("sending: {:?}", bytes);
    let _ = sock.send_to(&bytes, to)?;
    Ok(())
}

pub fn recv_from<T: serde::de::DeserializeOwned>(sock: &UdpSocket) -> Result<(T, SocketAddr)> {
    use std::cell::RefCell;
    thread_local! {
        static WORKING_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0; 1 << 16]);
    }

    WORKING_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        let buf = buf.as_mut_slice();
        let (sz, src) = sock.recv_from(buf)?;
        trace!("src={}", src);
        let msg: T = serde_cbor::from_slice(&buf[..sz])?;
        Ok((msg, src))
    })
}
