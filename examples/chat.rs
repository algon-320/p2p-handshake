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

fn spawn_heartbeat_thread(
    sock: Arc<UdpSocket>,
    key: Arc<Mutex<SymmetricKey>>,
    peer_addr: SocketAddr,
) {
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

fn text_chat(
    sock: UdpSocket,
    my_addr: SocketAddr,
    peer_addr: SocketAddr,
    preshared_key: String,
) -> Result<()> {
    assert_ne!(my_addr, peer_addr);
    let key_id = if my_addr < peer_addr { 0 } else { 1 };

    debug!("key_id = {}", key_id);
    let key = Arc::new(Mutex::new(SymmetricKey::new(
        preshared_key.as_bytes(),
        key_id,
    )?));
    let sock = Arc::new(sock);

    // spawn threads
    spawn_read_stdin_thread(sock.clone(), key.clone(), peer_addr);
    spawn_heartbeat_thread(sock.clone(), key.clone(), peer_addr);

    loop {
        let (enc_msg, src) = match recv_from::<Sealed<Message>>(&sock) {
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
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
            Message::Text(text) => {
                println!("\n{} --->: {:?}", src, text);
                print_prompt(peer_addr);
            }
        }
    }
}

fn main() -> Result<()> {
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

    let addr = matches.value_of("server-address").unwrap();
    let port: u16 = matches
        .value_of("server-port")
        .unwrap_or("31415")
        .parse::<u16>()
        .unwrap();
    let psk = matches.value_of("preshared-key").unwrap().to_owned();

    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    debug!("socket port = {}", sock.local_addr().unwrap().port());

    let mut server_addr = (addr, port).to_socket_addrs()?;
    let server_addr = server_addr.next().unwrap();

    let (my_addr, peer_addr) = get_peer_addr(&sock, server_addr, psk.clone())?;
    text_chat(sock, my_addr, peer_addr, psk)?;

    Ok(())
}
