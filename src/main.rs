use tokio::{net::UdpSocket, sync::mpsc};
use std::{fs, io::{self, Error, Read}, net::{IpAddr, SocketAddr}, sync::Arc, thread, time, str};
use std::process::Command;
use clap::{App, Arg};
use env_logger::Builder;
use log::{error, info, warn, LevelFilter};
use tun::platform::Device;
use serde_derive::Serialize;
use serde_derive::Deserialize;
use std::str::FromStr;

//mod tcp_client;
//mod tcp_server;
mod server;
mod client;

struct VpnPacket {
    data: Vec<u8>
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
    data: Vec<u8>
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

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum ServerMode {
    VPN,
    Hotspot
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ServerInterface {
    bind_address: String,
    internal_address: String,
    private_key: String,
    mode: ServerMode,
    broadcast_mode: bool,
    keepalive: u8
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ServerPeer {
    public_key: String,
    ip: IpAddr
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum ObfsProtocol {
    DNSMask,
    ICMPMask,
    VEIL
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ObfsConfig {
    protocol: ObfsProtocol
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ServerConfiguration {
    interface: ServerInterface,
    peers: Vec<ServerPeer>,
    obfs: ObfsConfig,
    dns: DNSConfig
}

impl ServerConfiguration {
    fn default() -> Self {
        ServerConfiguration { interface: ServerInterface { 
                bind_address: String::from_str("0.0.0.0:8879").unwrap(), 
                internal_address: String::from_str("10.8.0.1").unwrap(), 
                private_key: String::new(), 
                mode: ServerMode::VPN, 
                broadcast_mode: true, 
                keepalive: 10 
            }, 
            peers: Vec::new(), 
            obfs: ObfsConfig { protocol: ObfsProtocol::DNSMask }, 
            dns: DNSConfig { enabled: false, net_name: String::from_str("fridah.vpn").unwrap(), entries: Vec::new() } 
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct DNSConfig {
    enabled: bool,
    net_name: String,
    entries: Vec<DNSEntry>
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct DNSEntry {
    ip: IpAddr,
    subdomain: String
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ClientInterface {
    private_key: String,
    address: String
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct EndpointInterface {
    public_key: String,
    endpoint: String
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ClientConfiguration {
    client: ClientInterface,
    server: EndpointInterface
}

impl ClientConfiguration {
    fn default() -> Self {
        ClientConfiguration { client: ClientInterface { private_key: String::new(), address: String::from_str("10.8.0.2").unwrap() }, 
            server: EndpointInterface { public_key: String::new(), endpoint: String::from_str("192.168.0.2:8879").unwrap() } }
    }
}

#[tokio::main]
async fn main() {

    // Initialize the logger with 'info' as the default level
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();

    let matches = App::new("Frida VPN")
        .version("0.1.2")
        .author("alterwain")
        .about("VPN software")
        .arg(Arg::with_name("mode")
            .required(true)
            .index(1)
            .possible_values(&["server", "client"])
            .help("Runs the program in either server or client mode"))
        .arg(Arg::with_name("config")
            .long("config")
            .required(true)
            .value_name("FILE")
            .help("The path to VPN configuration file")
            .takes_value(true))
        .get_matches();

    let is_server_mode = matches.value_of("mode").unwrap() == "server";

    if let Some(config_path) = matches.value_of("config") {
        
        let data = fs::read(config_path);

        if data.is_err() {
            warn!("There is no config file. Generating it.");
            if is_server_mode {
                fs::write(config_path, serde_yaml::to_string(&ServerConfiguration::default()).unwrap());
                return;
            }
            fs::write(config_path, serde_yaml::to_string(&ClientConfiguration::default()).unwrap());
            return;
        }

        if is_server_mode {
            let config: ServerConfiguration = serde_yaml::from_str(&String::from_utf8(data.unwrap()).unwrap()).unwrap();
            server::server_mode(config).await;
            return;
        }
        let config: ClientConfiguration = serde_yaml::from_str(&String::from_utf8(data.unwrap()).unwrap()).unwrap();
        client::client_mode(config).await;
    }
}