use tokio::{net::UdpSocket, sync::mpsc};
use std::{io::{self, Read}, net::SocketAddr, sync::Arc, thread, time};
use std::process::Command;
use clap::{App, Arg};
use env_logger::Builder;
use log::{error, info, LevelFilter};
use tun::platform::Device;
use serde_derive::Serialize;
use serde_derive::Deserialize;

//mod client;
//mod server;
mod tcp_client;
mod tcp_server;

const HEADER: [u8;3] = [0x56, 0x66, 0x76];
const TAIL: [u8;3] = [0x76, 0x66, 0x56];

#[derive(Serialize, Deserialize)]
struct VpnPacket {
    start: Vec<u8>,
    data: Vec<u8>,
    end: Vec<u8>
}

impl VpnPacket {
    fn init(d: Vec<u8>) -> Self {
        VpnPacket{start: (&HEADER).to_vec(), data: d, end: (&TAIL).to_vec()}
    }
}

#[tokio::main]
async fn main() {

    // Initialize the logger with 'info' as the default level
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();

    let matches = App::new("Frida VPN")
        .version("1.0")
        .author("alterwain")
        .about("VPN software")
        .arg(Arg::with_name("mode")
            .required(true)
            .index(1)
            .possible_values(&["server", "client"])
            .help("Runs the program in either server or client mode"))
        .arg(Arg::with_name("vpn-server")
            .long("vpn-server")
            .value_name("IP")
            .help("The IP address of the VPN server to connect to (client mode only)")
            .takes_value(true))
        .get_matches();

    let is_server_mode = matches.value_of("mode").unwrap() == "server";
    // "192.168.0.4:8879"
    if is_server_mode {
        tcp_server::server_mode().await; 
    } else { 
        if let Some(vpn_server_ip) = matches.value_of("vpn-server") {
            let server_address = format!("{}:8879", vpn_server_ip);
            tcp_client::client_mode(server_address).await;
        } else {
            eprintln!("Error: For client mode, you shall provide the '--vpn-server' argument.");
        }
    }
}