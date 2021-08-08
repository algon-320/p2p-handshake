use log::{debug, error, info, warn};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::{
    crypto::{derive_symmetric_key, CounterNonce},
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
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    debug!("timeout");
                    continue 'resend;
                }
                Err(err) => return Err(err.into()),
                Ok((msg, _)) => return Ok(msg),
            }
        }
    }
}

pub fn get_peer_addr(sock: &UdpSocket, server_addr: SocketAddr, psk: String) -> Result<SocketAddr> {
    info!("psk = {:?}", psk);
    sock.set_read_timeout(Duration::from_secs(10).into())?;

    let matching_key = {
        use ring::digest::{digest, SHA256};
        digest(&SHA256, psk.as_bytes())
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

        let symmkey = derive_symmetric_key(client_sk, &server_pubkey)?;
        let mut counter = CounterNonce::default();

        let enc_matching_key = {
            use ring::aead::{Aad, NonceSequence};
            let mut bytes = matching_key.as_ref().to_vec();
            symmkey.seal_in_place_append_tag(counter.advance()?, Aad::empty(), &mut bytes)?;
            bytes
        };

        let request = ClientMessage::MatchRequest {
            pubkey: client_pk.as_ref().to_vec(),
            enc_matching_key,
        };

        let enc_peer_addr = {
            match send_and_receive(&request, &sock, server_addr) {
                Ok(ServerMessage::Matched { enc_peer_addr }) => enc_peer_addr,
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

        let peer_addr = {
            use ring::aead::{Aad, NonceSequence};
            let mut buf = enc_peer_addr;
            let slice = symmkey.open_in_place(counter.advance()?, Aad::empty(), &mut buf)?;

            use std::net::ToSocketAddrs;
            match std::str::from_utf8(slice)
                .ok()
                .and_then(|s| s.to_socket_addrs().ok())
                .and_then(|mut addrs| addrs.next())
            {
                Some(peer_addr) => peer_addr,
                None => {
                    error!("Invalid peer address");
                    continue 'main;
                }
            }
        };

        info!("matched: {}", peer_addr);
        return Ok(peer_addr);
    }
}

pub fn example(sock: UdpSocket, addr: SocketAddr) -> Result<()> {
    #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
    enum Message {
        Heartbeat,
        Finish,
        Text(String),
        Data(Vec<u8>),
    }

    let sock = std::sync::Arc::new(sock);

    use std::thread::{sleep, spawn};

    // stdio interaction
    {
        let sock = sock.clone();
        spawn(move || -> Result<()> {
            loop {
                use std::io::{stdin, stdout, Read, Write};
                write!(stdout(), "> ")?;
                stdout().flush()?;

                let mut buffer = String::new();
                stdin().read_to_string(&mut buffer)?;

                send_to(Message::Text(buffer), &sock, addr)?;
            }
        });
    }

    // heartbeat
    {
        let sock = sock.clone();
        spawn(move || -> Result<()> {
            loop {
                send_to(Message::Heartbeat, &sock, addr)?;
                sleep(Duration::from_secs(5));
            }
        });
    }

    loop {
        let (msg, src) = match recv_from::<Message>(&sock) {
            Err(err) => {
                error!("{}", err);
                sleep(Duration::from_secs(1));
                continue;
            }
            Ok(ok) => ok,
        };

        match msg {
            Message::Heartbeat => {
                info!("Heatbeat from {}", src);
            }
            Message::Data(data) => {
                println!("\nfrom {}: data = {:?}", src, data);
            }
            Message::Text(text) => {
                println!("\nfrom {}: text = {:?}", src, text);
            }
            Message::Finish => {
                return Ok(());
            }
        }
    }
}
