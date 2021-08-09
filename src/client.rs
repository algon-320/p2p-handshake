use log::{debug, error, info, warn};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::{
    crypto::derive_symmetric_key,
    error::{Error, Result},
    message::{recv_from, send_to, ClientMessage, ServerMessage},
};

fn send_and_receive(
    msg: &ClientMessage,
    sock: &UdpSocket,
    server_addr: SocketAddr,
) -> Result<ServerMessage> {
    'resend: loop {
        info!("sending a message ...");
        send_to(msg, &sock, server_addr)?;

        info!("waiting for server response ...");
        'wait: loop {
            match recv_from::<ServerMessage>(&sock) {
                Ok((_, src)) if src != server_addr => {
                    warn!("message from other than the server: {}", src);
                    continue 'wait;
                }
                Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    debug!("timeout");
                    continue 'resend;
                }
                Err(err) => return Err(err),
                Ok((msg, _)) => return Ok(msg),
            }
        }
    }
}

pub fn get_peer_addr(
    sock: &UdpSocket,
    server_addr: SocketAddr,
    psk: String,
) -> Result<(SocketAddr, SocketAddr)> {
    info!("psk = {:?}", psk);
    sock.set_read_timeout(Duration::from_secs(10).into())?;

    let matching_key = {
        use ring::digest::{digest, SHA256};
        digest(&SHA256, psk.as_bytes()).as_ref().to_vec()
    };

    'main: loop {
        let (client_sk, client_pk) = {
            use ring::agreement::{EphemeralPrivateKey, X25519};
            let rng = ring::rand::SystemRandom::new();
            let client_sk = EphemeralPrivateKey::generate(&X25519, &rng)?;
            let client_pk = client_sk.compute_public_key()?;
            (client_sk, client_pk)
        };

        let server_pubkey = {
            match send_and_receive(&ClientMessage::Hello, &sock, server_addr) {
                Ok(ServerMessage::ServerPubKey { pubkey }) => pubkey,
                Ok(_) => {
                    error!("{}", Error::UnexpectedMessage);
                    continue 'main;
                }
                Err(err) => {
                    error!("{}", err);
                    std::thread::sleep(Duration::from_secs(3));
                    continue 'main;
                }
            }
        };

        let mut symmkey = derive_symmetric_key(client_sk, &server_pubkey, 0)?;

        let request = ClientMessage::MatchRequest {
            pubkey: client_pk.as_ref().to_vec(),
            enc_matching_key: symmkey.encrypt(matching_key.clone())?,
        };

        let (my_addr, peer_addr) = {
            match send_and_receive(&request, &sock, server_addr) {
                Ok(ServerMessage::Matched {
                    enc_your_addr,
                    enc_peer_addr,
                }) => (
                    symmkey.decrypt(enc_your_addr)?,
                    symmkey.decrypt(enc_peer_addr)?,
                ),
                Ok(_) => {
                    error!("{}", Error::UnexpectedMessage);
                    continue 'main;
                }
                Err(err) => {
                    error!("{}", err);
                    continue 'main;
                }
            }
        };

        info!("my addr: {}, peer addr: {}", my_addr, peer_addr);
        return Ok((my_addr, peer_addr));
    }
}
