mod client;
mod message;
mod crypto;
mod error;
mod server;

use log::{debug, error};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    use clap::{App, Arg, SubCommand};

    let matches = App::new("p2p-handshake")
        .version(env!("CARGO_PKG_VERSION"))
        .author("algon-320 <algon.0320@mail.com>")
        .subcommand(
            SubCommand::with_name("server").arg(
                Arg::with_name("port")
                    .short("p")
                    .long("port")
                    .takes_value(true)
                    .required(false),
            ),
        )
        .subcommand(
            SubCommand::with_name("client")
                .arg(
                    Arg::with_name("server-address")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("server-port")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("preshared-key")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("server", Some(matches)) => {
            let port_s = matches.value_of("port").unwrap_or("31415");
            let port = match port_s.parse::<u16>() {
                Ok(p) => p,
                Err(err) => {
                    error!("Invalid port number: {}", err);
                    return Ok(());
                }
            };
            if let Err(e) = server::server(port) {
                error!("{}", e);
            }
        }

        ("client", Some(matches)) => {
            use std::net::{Ipv4Addr, ToSocketAddrs, UdpSocket};

            let addr = matches.value_of("server-address").unwrap();
            let port: u16 = matches
                .value_of("server-port")
                .unwrap_or("31415")
                .parse::<u16>()?;
            let preshared_key = matches.value_of("preshared-key").unwrap().to_owned();

            let mut server_sockaddr = (addr, port).to_socket_addrs()?;
            let server_sockaddr = server_sockaddr.next().unwrap();

            let sample_client = || -> error::Result<()> {
                let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
                debug!("socket port = {}", sock.local_addr().unwrap().port());

                let peer_addr = client::get_peer_addr(&sock, server_sockaddr, preshared_key)?;
                client::example(&sock, peer_addr)
            };

            if let Err(e) = sample_client() {
                error!("{}", e);
            }
        }

        _ => unreachable!(),
    }
    Ok(())
}
