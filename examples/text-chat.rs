use log::{debug, error, info};
use std::io::prelude::*;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn};
use std::time::Duration;

use p2p_handshake::{
    client::get_peer_addr,
    crypto::{Sealed, SymmetricKey},
    error::{Error, Result},
    message::{recv_from, send_to},
};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
enum Message {
    Heartbeat,
    Text(String),
}

fn print_prompt(addr: SocketAddr) {
    print!("{} <---: ", addr);
    std::io::stdout().flush().unwrap();
}

fn spawn_read_stdin_thread(
    sock: Arc<UdpSocket>,
    key: Arc<Mutex<SymmetricKey>>,
    peer_addr: SocketAddr,
) {
    println!("Simple text chat example");
    println!("[Ctrl-d to transfer the text]");
    spawn(move || {
        || -> Result<()> {
            loop {
                print_prompt(peer_addr);

                let mut buffer = String::new();
                std::io::stdin().read_to_string(&mut buffer)?;

                let mut key = key.lock().unwrap();
                let enc_msg = key.encrypt(Message::Text(buffer))?;
                send_to(enc_msg, &sock, peer_addr)?;
            }
        }()
        .unwrap_or_else(|e| error!("stdin thread panicked: {}", e))
    });
}

fn spawn_heartbeat_thread(
    sock: Arc<UdpSocket>,
    key: Arc<Mutex<SymmetricKey>>,
    peer_addr: SocketAddr,
) {
    spawn(move || {
        || -> Result<()> {
            loop {
                {
                    let mut key = key.lock().unwrap();
                    let enc_msg = key.encrypt(Message::Heartbeat)?;
                    send_to(enc_msg, &sock, peer_addr)?;
                }
                sleep(Duration::from_secs(5));
            }
        }()
        .unwrap_or_else(|e| error!("heartbeat thread panicked: {}", e))
    });
}

fn text_chat(
    sock: UdpSocket,
    my_addr: SocketAddr,
    peer_addr: SocketAddr,
    preshared_key: String,
) -> Result<()> {
    let sock = Arc::new(sock);

    // `key_id` is needed to agree the same "direction" of encryption on both sides.
    assert_ne!(my_addr, peer_addr);
    let key_id = if my_addr < peer_addr { 0 } else { 1 };
    debug!("key_id = {}", key_id);

    // derive a symmetric key for encryption of messages
    let key = SymmetricKey::new(preshared_key.as_bytes(), key_id)?;
    let key = Arc::new(Mutex::new(key));

    // spawn threads
    spawn_read_stdin_thread(sock.clone(), key.clone(), peer_addr);
    spawn_heartbeat_thread(sock.clone(), key.clone(), peer_addr);

    'process_message: loop {
        let (enc_msg, src) = match recv_from::<Sealed<Message>>(&sock) {
            Ok(ok) => ok,
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
                debug!("timeout");
                continue 'process_message;
            }
            Err(err) => {
                error!("{}", err);
                sleep(Duration::from_secs(1));
                continue 'process_message;
            }
        };

        if src != peer_addr {
            error!("message from other than the expected peer. ignored.");
            continue 'process_message;
        }

        // decrypt received message
        let msg = {
            let key = key.lock().unwrap();
            match key.decrypt(enc_msg) {
                Ok(msg) => msg,
                Err(err) => {
                    error!("invalid message: {}", err);
                    continue 'process_message;
                }
            }
        };

        match msg {
            Message::Heartbeat => {
                info!("Heatbeat from {}", src);
            }
            Message::Text(text) => {
                println!("\n{} --->: {:?}", src, text);
                print_prompt(peer_addr);
            }
        }
    }
}

fn start(matches: clap::ArgMatches) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    debug!("socket port = {}", sock.local_addr().unwrap().port());

    let psk = matches
        .value_of("preshared-key")
        .expect("required arg")
        .to_owned();

    let server_sockaddr = {
        let addr = matches.value_of("server-address").expect("required arg");
        let port = matches.value_of("server-port").expect("required arg");
        let port = port.parse::<u16>()?;
        (addr, port).to_socket_addrs()?.next().unwrap()
    };

    // get peer's address and port number
    let (my_addr, peer_addr) = get_peer_addr(&sock, server_sockaddr, psk.clone())?;

    // start text chating
    text_chat(sock, my_addr, peer_addr, psk)?;
    Ok(())
}

fn main() {
    env_logger::init();

    let matches = clap::App::new("p2p-chat-example")
        .version(env!("CARGO_PKG_VERSION"))
        .author("algon-320 <algon.0320@mail.com>")
        .arg(
            clap::Arg::with_name("server-address")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("server-port")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("preshared-key")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    match start(matches) {
        Ok(()) => {}
        Err(err) => {
            error!("{}", err);
        }
    }
}
