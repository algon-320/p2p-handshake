use log::trace;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, UdpSocket};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ClientMessage {
    Hello,
    MatchRequest {
        pubkey: Vec<u8>,
        enc_matching_key: Vec<u8>,
    },

    #[cfg(feature = "debugging")]
    Initialize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ServerMessage {
    ServerPubKey { pubkey: Vec<u8> },
    Matched { enc_peer_addr: Vec<u8> },
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

pub fn derive_symmetric_key(
    sk: ring::agreement::EphemeralPrivateKey,
    pk: &[u8],
) -> Result<ring::aead::LessSafeKey, ring::error::Unspecified> {
    use ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM};
    use ring::agreement::{agree_ephemeral, UnparsedPublicKey, X25519};
    use ring::pbkdf2::{derive, PBKDF2_HMAC_SHA256};

    let pk = UnparsedPublicKey::new(&X25519, pk);
    agree_ephemeral(sk, &pk, ring::error::Unspecified, |common_material| {
        let mut key_bytes: [u8; 32] = [0; 32];
        derive(
            PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100000).unwrap(),
            &[],
            &common_material,
            &mut key_bytes,
        );
        let key = UnboundKey::new(&AES_256_GCM, &key_bytes)?;
        Ok(LessSafeKey::new(key))
    })
}

#[derive(Debug, Default)]
pub struct CounterNonce(u64);

impl ring::aead::NonceSequence for CounterNonce {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        self.0 = self.0.checked_add(1).ok_or(ring::error::Unspecified)?;
        let b = self.0.to_ne_bytes();
        Ok(ring::aead::Nonce::assume_unique_for_key([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], 0, 0, 0, 0,
        ]))
    }
}
