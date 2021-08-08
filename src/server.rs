use log::{debug, error, info};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use crate::{
    crypto::{derive_symmetric_key, Sealed, SymmetricKey},
    error::Result,
    message::{recv_from, send_to, ClientMessage, ServerMessage},
};

#[derive(Debug)]
enum State {
    Pending {
        server_sk: ring::agreement::EphemeralPrivateKey,
    },
    Waiting {
        enc_matching_key: Sealed<Vec<u8>>,
        symmetric_key: Box<SymmetricKey>,
    },
    Matched {
        enc_your_addr: Sealed<SocketAddr>,
        enc_peer_addr: Sealed<SocketAddr>,
    },
}

pub fn server(port: u16) -> Result<()> {
    info!("listening port = {}", port);
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))?;

    let rng = ring::rand::SystemRandom::new();
    let mut states: HashMap<SocketAddr, State> = HashMap::new();
    let mut waiting: HashMap<Vec<u8>, SocketAddr> = HashMap::new();

    loop {
        let (msg, src) = match recv_from::<ClientMessage>(&sock) {
            Err(err) => {
                error!("{}", err);
                continue;
            }
            Ok(ok) => ok,
        };
        debug!("from: {:?}, msg: {:?}", src, msg);

        match msg {
            #[cfg(feature = "debugging")]
            ClientMessage::Initialize => {
                log::warn!("initialize request received");
                states.clear();
                waiting.clear();
            }

            ClientMessage::Hello => match states.get(&src) {
                None => {
                    let (server_sk, server_pk) = {
                        use ring::agreement::{EphemeralPrivateKey, X25519};
                        let server_sk = EphemeralPrivateKey::generate(&X25519, &rng)?;
                        let server_pk = server_sk.compute_public_key()?;
                        (server_sk, server_pk)
                    };
                    states.insert(src, State::Pending { server_sk });
                    let pubkey_msg = ServerMessage::ServerPubKey {
                        pubkey: server_pk.as_ref().to_vec(),
                    };
                    send_to(&pubkey_msg, &sock, src)?;
                }

                Some(State::Pending { server_sk }) => {
                    let server_pk = server_sk.compute_public_key()?;
                    let pubkey_msg = ServerMessage::ServerPubKey {
                        pubkey: server_pk.as_ref().to_vec(),
                    };
                    send_to(&pubkey_msg, &sock, src)?;
                }

                Some(_) => {
                    debug!("ignored invalid message");
                    continue;
                }
            },

            ClientMessage::MatchRequest {
                pubkey: client_pk,
                enc_matching_key,
            } if states.contains_key(&src) => match &states[&src] {
                State::Matched {
                    enc_your_addr,
                    enc_peer_addr,
                } => {
                    let msg = ServerMessage::Matched {
                        enc_your_addr: enc_your_addr.clone(),
                        enc_peer_addr: enc_peer_addr.clone(),
                    };
                    send_to(msg, &sock, src)?;
                }

                State::Waiting { .. } => {
                    continue;
                }

                State::Pending { .. } => {
                    let server_sk = match states.remove(&src) {
                        Some(State::Pending { server_sk }) => server_sk,
                        _ => unreachable!(),
                    };
                    let symmkey = derive_symmetric_key(server_sk, &client_pk, 1)?;

                    let psk = symmkey.decrypt(enc_matching_key.clone())?;

                    if waiting.contains_key(&psk) {
                        let peer1 = waiting.remove(&psk).unwrap();
                        let peer2 = src;
                        info!("matched: {} <---> {}", peer1, peer2);

                        let mut key1 = match states.remove(&peer1) {
                            Some(State::Waiting { symmetric_key, .. }) => *symmetric_key,
                            _ => {
                                error!("Invalid state");
                                continue;
                            }
                        };
                        let mut key2 = symmkey;

                        // tell {peer1} its peer is {peer2}
                        let enc_your_addr = key1.encrypt(peer1)?;
                        let enc_peer_addr = key1.encrypt(peer2)?;
                        let state = State::Matched {
                            enc_your_addr: enc_your_addr.clone(),
                            enc_peer_addr: enc_peer_addr.clone(),
                        };
                        states.insert(peer1, state);
                        let msg = ServerMessage::Matched {
                            enc_your_addr,
                            enc_peer_addr,
                        };
                        send_to(msg, &sock, peer1)?;

                        // tell {peer2} its peer is {peer1}
                        let enc_your_addr = key2.encrypt(peer2)?;
                        let enc_peer_addr = key2.encrypt(peer1)?;
                        let state = State::Matched {
                            enc_your_addr: enc_your_addr.clone(),
                            enc_peer_addr: enc_peer_addr.clone(),
                        };
                        states.insert(peer2, state);
                        let msg = ServerMessage::Matched {
                            enc_your_addr,
                            enc_peer_addr,
                        };
                        send_to(msg, &sock, peer2)?;
                    } else {
                        let state = State::Waiting {
                            enc_matching_key,
                            symmetric_key: Box::new(symmkey),
                        };
                        states.insert(src, state);
                        waiting.insert(psk, src);
                    }
                }
            },

            _ => {
                debug!("ignored invalid message: {:?}", msg);
            }
        }
    }
}
