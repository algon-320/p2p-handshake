use log::{debug, error, info, warn};
use std::io::prelude::*;
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

pub fn example(
    sock: UdpSocket,
    my_addr: SocketAddr,
    peer_addr: SocketAddr,
    preshared_key: String,
) -> Result<()> {
    use crate::crypto::{Sealed, SymmetricKey};
    use std::sync::{Arc, Mutex};
    use std::thread::{sleep, spawn};

    #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
    enum Message {
        Heartbeat,
        Finish,
        Text(String),
        Data(Vec<u8>),
    }

    fn print_prompt(addr: SocketAddr) {
        print!("{} <---: ", addr);
        std::io::stdout().flush().unwrap();
    }

    assert_ne!(my_addr, peer_addr);
    let key_id = if my_addr < peer_addr { 0 } else { 1 };
    debug!("key_id = {}", key_id);
    let key = Arc::new(Mutex::new(SymmetricKey::new(
        preshared_key.as_bytes(),
        key_id,
    )?));
    let sock = Arc::new(sock);

    // stdio interaction
    {
        println!("Simple text chat example");
        println!("[Ctrl-d to transfer the text]");
        let sock = sock.clone();
        let key = key.clone();
        spawn(move || -> Result<()> {
            loop {
                print_prompt(peer_addr);

                let mut buffer = String::new();
                std::io::stdin().read_to_string(&mut buffer)?;

                let mut key = key.lock().unwrap();
                let enc_msg = key.encrypt(Message::Text(buffer))?;
                send_to(enc_msg, &sock, peer_addr)?;
            }
        });
    }

    // heartbeat
    {
        let sock = sock.clone();
        let key = key.clone();
        spawn(move || -> Result<()> {
            loop {
                {
                    let mut key = key.lock().unwrap();
                    let enc_msg = key.encrypt(Message::Heartbeat)?;
                    send_to(enc_msg, &sock, peer_addr)?;
                }
                sleep(Duration::from_secs(5));
            }
        });
    }

    loop {
        let (enc_msg, src) = match recv_from::<Sealed<Message>>(&sock) {
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                debug!("timeout");
                continue;
            }
            Err(err) => {
                error!("{}", err);
                sleep(Duration::from_secs(1));
                continue;
            }
            Ok(ok) => ok,
        };
        let msg = key.lock().unwrap().decrypt(enc_msg)?;

        match msg {
            Message::Heartbeat => {
                info!("Heatbeat from {}", src);
            }
            Message::Data(data) => {
                println!("\n{} --->: {:?}", src, data);
                print_prompt(peer_addr);
            }
            Message::Text(text) => {
                println!("\n{} --->: {:?}", src, text);
                print_prompt(peer_addr);
            }
            Message::Finish => {
                return Ok(());
            }
        }
    }
}
