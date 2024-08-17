use tokio::{net::UdpSocket, sync::mpsc};
use std::{io::{self, Error, Read}, net::SocketAddr, sync::Arc, thread, time};
use std::process::Command;
use clap::{App, Arg};
use env_logger::Builder;
use log::{error, info, LevelFilter};
use tun::platform::Device;
use serde_derive::Serialize;
use serde_derive::Deserialize;

mod tcp_client;
mod tcp_server;
mod server;
mod client;

struct VpnPacket {
    //start: Vec<u8>
    data: Vec<u8>
    //end: Vec<u8>
}

impl VpnPacket {
    fn serialize(&self) -> Vec<u8> {
        let len: [u8; 8] = (self.data.len() as u64).to_be_bytes();
        len.iter().cloned().chain(self.data.iter().cloned()).collect()
    }

    fn deserialize_length(d: [u8; 8]) -> u64 {
        u64::from_be_bytes(d)
    }

    fn deserialize(d: Vec<u8>) -> Result<VpnPacket, Error> {
        Ok(VpnPacket{ data: d })
    }
}


struct UDPVpnPacket {
    //start: Vec<u8>
    data: Vec<u8>
    //end: Vec<u8>
}

impl UDPVpnPacket {
    fn serialize(&self) -> Vec<u8> {
        let h: &[u8] = &[1];
        [h, &self.data[..]].concat()
    }
}

struct UDPVpnHandshake {}

impl UDPVpnHandshake {
    fn serialize(&self) -> Vec<u8> {
        [0, 9, 9, 9, 9, 9, 9].to_vec()
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
            server::server_mode(server_address).await;
        } else {
            eprintln!("Error: For server mode, you shall provide the '--bind-to' argument.");
        }
         
    } else { 
        if let Some(vpn_server_ip) = matches.value_of("vpn-server") {
            let server_address = format!("{}:8879", vpn_server_ip);
            client::client_mode(server_address).await;
        } else {
            eprintln!("Error: For client mode, you shall provide the '--vpn-server' argument.");
        }
    }
}