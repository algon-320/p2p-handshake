use log::{debug, error, info, warn};
use std::io::prelude::*;
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

pub fn example(sock: UdpSocket, addr: SocketAddr, preshared_key: String) -> Result<()> {
    use ring::{aead, pbkdf2};
    use std::sync::{Arc, Mutex};
    use std::thread::{sleep, spawn};

    #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
    enum Message {
        Heartbeat,
        Finish,
        Text(String),
        Data(Vec<u8>),
    }

    #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
    struct EncryptedMessage {
        nonce: [u8; 12],
        bytes: Vec<u8>,
    }

    struct Key {
        key: ring::aead::LessSafeKey,
        counter: CounterNonce,
    }

    impl Key {
        fn new(psk: String) -> Result<Self> {
            let mut key_bytes: [u8; 32] = [0; 32];
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA256,
                std::num::NonZeroU32::new(100000).unwrap(),
                &[],
                psk.as_bytes(),
                &mut key_bytes,
            );
            let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)?;
            let key = aead::LessSafeKey::new(key);
            Ok(Self {
                key,
                counter: CounterNonce::default(),
            })
        }

        fn encrypt(&mut self, msg: Message) -> Result<EncryptedMessage> {
            use aead::NonceSequence;
            let nonce = self.counter.advance()?;
            let nonce_bytes = *nonce.as_ref();
            let aad = aead::Aad::from(nonce_bytes);

            let mut bytes = serde_json::to_vec(&msg).map_err(std::io::Error::from)?;
            self.key.seal_in_place_append_tag(nonce, aad, &mut bytes)?;

            Ok(EncryptedMessage {
                nonce: nonce_bytes,
                bytes,
            })
        }

        fn decrypt(&mut self, enc_msg: EncryptedMessage) -> Result<Message> {
            let mut buf = enc_msg.bytes;
            let aad = aead::Aad::from(enc_msg.nonce);
            let nonce = aead::Nonce::assume_unique_for_key(enc_msg.nonce);
            let slice = self.key.open_in_place(nonce, aad, &mut buf)?;
            let msg: Message = serde_json::from_slice(slice).map_err(std::io::Error::from)?;
            Ok(msg)
        }
    }

    fn print_prompt(addr: SocketAddr) {
        print!("{} <---: ", addr);
        std::io::stdout().flush().unwrap();
    }

    let key = Arc::new(Mutex::new(Key::new(preshared_key)?));
    let sock = Arc::new(sock);

    // stdio interaction
    {
        println!("Simple text chat example");
        println!("[Ctrl-d to transfer the text]");
        let sock = sock.clone();
        let key = key.clone();
        spawn(move || -> Result<()> {
            loop {
                print_prompt(addr);

                let mut buffer = String::new();
                std::io::stdin().read_to_string(&mut buffer)?;

                let mut key = key.lock().unwrap();
                let enc_msg = key.encrypt(Message::Text(buffer))?;
                send_to(enc_msg, &sock, addr)?;
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
                    send_to(enc_msg, &sock, addr)?;
                }
                sleep(Duration::from_secs(5));
            }
        });
    }

    loop {
        let (enc_msg, src) = match recv_from::<EncryptedMessage>(&sock) {
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
                print_prompt(addr);
            }
            Message::Text(text) => {
                println!("\n{} --->: {:?}", src, text);
                print_prompt(addr);
            }
            Message::Finish => {
                return Ok(());
            }
        }
    }
}
