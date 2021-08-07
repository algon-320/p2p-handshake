use log::{debug, error, info};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use crate::{
    common::{
        derive_symmetric_key, recv_from, send_to, ClientMessage, CounterNonce, ServerMessage,
    },
    error::Result,
};

#[derive(Debug)]
enum State {
    Pending {
        server_sk: ring::agreement::EphemeralPrivateKey,
    },
    Waiting {
        enc_matching_key: Vec<u8>,
        symmetric_key: Box<(ring::aead::LessSafeKey, CounterNonce)>,
    },
    Matched {
        enc_peer_addr: Vec<u8>,
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
                State::Matched { enc_peer_addr } => {
                    send_to(
                        ServerMessage::Matched {
                            enc_peer_addr: enc_peer_addr.clone(),
                        },
                        &sock,
                        src,
                    )?;
                }

                State::Waiting {
                    enc_matching_key: emk,
                    ..
                } if &enc_matching_key == emk => {
                    continue;
                }

                State::Waiting { .. } | State::Pending { .. } => {
                    let server_sk = match states.remove(&src) {
                        Some(State::Pending { server_sk }) => server_sk,
                        _ => unreachable!(),
                    };

                    let symmkey = derive_symmetric_key(server_sk, &client_pk)?;
                    let mut counter = CounterNonce::default();

                    let psk = {
                        use ring::aead::NonceSequence;
                        let mut buf = enc_matching_key.clone();
                        symmkey
                            .open_in_place(counter.advance()?, ring::aead::Aad::empty(), &mut buf)?
                            .to_vec()
                    };

                    if waiting.contains_key(&psk) {
                        let peer1 = waiting.remove(&psk).unwrap();
                        let peer2 = src;
                        info!("matched: {} <---> {}", peer1, peer2);

                        let (key1, mut ctr1) = match states.remove(&peer1) {
                            Some(State::Waiting { symmetric_key, .. }) => *symmetric_key,
                            _ => {
                                error!("Invalid state");
                                continue;
                            }
                        };
                        let (key2, mut ctr2) = (symmkey, counter);

                        use ring::aead::{Aad, NonceSequence};

                        // tell {peer1} its peer is {peer2}
                        let enc_peer_addr = {
                            let mut bytes = peer2.to_string().into_bytes();
                            key1.seal_in_place_append_tag(
                                ctr1.advance()?,
                                Aad::empty(),
                                &mut bytes,
                            )?;
                            bytes
                        };
                        states.insert(
                            peer1,
                            State::Matched {
                                enc_peer_addr: enc_peer_addr.clone(),
                            },
                        );
                        send_to(ServerMessage::Matched { enc_peer_addr }, &sock, peer1)?;

                        // tell {peer2} its peer is {peer1}
                        let enc_peer_addr = {
                            let mut bytes = peer1.to_string().into_bytes();
                            key2.seal_in_place_append_tag(
                                ctr2.advance()?,
                                Aad::empty(),
                                &mut bytes,
                            )?;
                            bytes
                        };
                        states.insert(
                            peer2,
                            State::Matched {
                                enc_peer_addr: enc_peer_addr.clone(),
                            },
                        );
                        send_to(ServerMessage::Matched { enc_peer_addr }, &sock, peer2)?;
                    } else {
                        states.insert(
                            src,
                            State::Waiting {
                                enc_matching_key,
                                symmetric_key: Box::new((symmkey, counter)),
                            },
                        );
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
