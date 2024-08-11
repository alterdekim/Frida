use tokio::{net::UdpSocket, sync::mpsc};
use std::{io::{self, Read}, net::SocketAddr, sync::Arc, thread, time};
use std::process::Command;
use clap::{App, Arg};
use env_logger::Builder;
use log::{error, info, LevelFilter};
use tun::platform::Device;
use serde_derive::Serialize;
use serde_derive::Deserialize;

mod client;
mod server;

#[derive(Serialize, Deserialize)]
struct VpnPacket {
    data: Vec<u8>,
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
        server::server_mode().await; 
    } else { 
        if let Some(vpn_server_ip) = matches.value_of("vpn-server") {
            let server_address = format!("{}:8879", vpn_server_ip);
            client::client_mode(server_address).await;
        } else {
            eprintln!("Error: For client mode, you shall provide the '--vpn-server' argument.");
        }
    }
}