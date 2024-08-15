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
mod eth_util;

const HEADER: [u8;3] = [0x56, 0x66, 0x76];
const TAIL: [u8;3] = [0x76, 0x66, 0x56];

#[derive(Serialize, Deserialize)]
struct VpnPacket {
    //start: Vec<u8>
    len: u64,
    data: Vec<u8>
    //end: Vec<u8>
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
        .arg(Arg::with_name("bind-to")
            .long("bind-to")
            .value_name("IP")
            .help("The IP address of the VPN server to bind to (server mode only)")
            .takes_value(true))
        .get_matches();

    let is_server_mode = matches.value_of("mode").unwrap() == "server";
    // "192.168.0.4:8879"
    if is_server_mode {
        if let Some(vpn_server_ip) = matches.value_of("bind-to") {
            let server_address = format!("{}:8879", vpn_server_ip);
            tcp_server::server_mode(server_address).await;
        } else {
            eprintln!("Error: For server mode, you shall provide the '--bind-to' argument.");
        }
         
    } else { 
        if let Some(vpn_server_ip) = matches.value_of("vpn-server") {
            let server_address = format!("{}:8879", vpn_server_ip);
            tcp_client::client_mode(server_address).await;
        } else {
            eprintln!("Error: For client mode, you shall provide the '--vpn-server' argument.");
        }
    }
}