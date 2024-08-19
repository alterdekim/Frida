use tokio::{net::UdpSocket, sync::mpsc};
use std::{fs, io::{self, Error, Read}, net::{IpAddr, Ipv4Addr, SocketAddr}, str, sync::Arc, thread, time};
use std::process::Command;
use clap::{App, Arg, ArgMatches};
use env_logger::Builder;
use log::{error, info, warn, LevelFilter};
use tun::platform::Device;
use serde_derive::Serialize;
use serde_derive::Deserialize;
use std::str::FromStr;
use x25519_dalek::{StaticSecret, PublicKey};
use rand::{rngs::StdRng, SeedableRng};
use base64;

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

impl UDPSerializable for UDPVpnPacket {
    fn serialize(&self) -> Vec<u8> {
        let h: &[u8] = &[1];
        [h, &self.data[..]].concat()
    }
}

struct UDPVpnHandshake {
    public_key: Vec<u8>
}

impl UDPSerializable for UDPVpnHandshake {
    fn serialize(&self) -> Vec<u8> {
        let h: &[u8] = &[0];
        [h, &self.public_key[..]].concat()
    }
}

trait UDPSerializable {
    fn serialize(&self) -> Vec<u8>;
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ServerInterface {
    bind_address: String,
    internal_address: String,
    private_key: String,
    public_key: String,
    broadcast_mode: bool,
    keepalive: u8
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ServerPeer {
    public_key: String,
    ip: Ipv4Addr
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
    fn default(bind_address: &str, internal_address: &str, broadcast_mode: bool, keepalive: u8, obfs_type: ObfsProtocol) -> Self {
        let mut csprng = StdRng::from_entropy();
        let secret = StaticSecret::new(&mut csprng);
        ServerConfiguration { interface: ServerInterface { 
                bind_address: String::from_str(bind_address).unwrap(), 
                internal_address: String::from_str(internal_address).unwrap(), 
                private_key: base64::encode(secret.as_bytes()), 
                public_key: base64::encode(PublicKey::from(&secret).as_bytes()),
                broadcast_mode, 
                keepalive 
            }, 
            peers: Vec::new(), 
            obfs: ObfsConfig { protocol: obfs_type }, 
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
    ip: Ipv4Addr,
    subdomain: String
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ClientInterface {
    private_key: String,
    public_key: String,
    address: String
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct EndpointInterface {
    public_key: String,
    endpoint: String,
    keepalive: u8
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ClientConfiguration {
    client: ClientInterface,
    server: EndpointInterface
}

impl ClientConfiguration {
    fn default(endpoint: &str, keepalive: u8, public_key: &str, internal_address: &str) -> Self {
        let mut csprng = StdRng::from_entropy();
        let secret = StaticSecret::new(&mut csprng);
        ClientConfiguration { 
            client: ClientInterface { 
                private_key: base64::encode(secret.as_bytes()), 
                public_key: base64::encode(PublicKey::from(&secret).as_bytes()),
                address: String::from_str(internal_address).unwrap() 
            }, 
            server: EndpointInterface { 
                public_key: String::from_str(public_key).unwrap(), 
                endpoint: String::from_str(endpoint).unwrap(),
                keepalive
            } 
        }
    }
}

fn generate_server_config(matches: &ArgMatches, config_path: &str) {
    let bind_address = matches.value_of("bind-address").expect("No bind address specified");
    let internal_address = matches.value_of("internal-address").expect("No internal address specified");
    let broadcast_mode = matches.value_of("broadcast-mode").is_some();
    let keepalive: u8 = matches.value_of("keepalive").unwrap().parse().expect("Keepalive argument should be a number");
    let obfs_type = match matches.value_of("obfs-type").expect("Obfs type should be specified") {
        "dns" => ObfsProtocol::DNSMask,
        "icmp" => ObfsProtocol::ICMPMask,
        _ => ObfsProtocol::VEIL
    };

    fs::write(config_path, serde_yaml::to_string(&ServerConfiguration::default(bind_address, internal_address, broadcast_mode, keepalive, obfs_type)).unwrap());
}

fn generate_peer_config(matches: &ArgMatches, config_path: &str, cfg_raw: &String) {
    let keepalive: u8 = matches.value_of("keepalive").unwrap().parse().expect("Keepalive argument should be a number");
    let grab_endpoint = matches.value_of("grab-endpoint").is_some();
    let endpoint = matches.value_of("endpoint").or(Some("0.0.0.0:0")).unwrap();
    let peer_cfg = matches.value_of("peer-cfg").expect("No peer cfg path specified");

    let mut config: ServerConfiguration = serde_yaml::from_str(cfg_raw).expect("Bad server config file structure");

    let mut prs = &mut config.peers[..];
    prs.sort_by(|a, b| a.ip.octets()[3].cmp(&b.ip.octets()[3]));
    
    let mut internal_address = prs.iter()
                                    .map(|p| p.ip)
                                    .collect::<Vec<Ipv4Addr>>()
                                    .first()
                                    .or(Some(&config.interface.internal_address.parse::<Ipv4Addr>().unwrap()))
                                    .unwrap()
                                    .clone();

    internal_address = Ipv4Addr::new(internal_address.octets()[0], internal_address.octets()[1], internal_address.octets()[2], internal_address.octets()[3]+1);

    let cl_cfg = &ClientConfiguration::default(if grab_endpoint { &config.interface.bind_address } else { endpoint }, 
        keepalive, 
        &config.interface.public_key, 
        &internal_address.to_string());

    config.peers.push(ServerPeer { public_key: cl_cfg.client.public_key.clone(), ip: internal_address.clone() });

    fs::write(peer_cfg, serde_yaml::to_string(cl_cfg).unwrap());

    fs::write(config_path, serde_yaml::to_string(&config).unwrap());
}

async fn init_server(cfg_raw: &str ) {
    let config: ServerConfiguration = serde_yaml::from_str(cfg_raw).expect("Bad server config file structure");
    server::server_mode(config).await;
}

async fn init_client(cfg_raw: &str) {
    let config: ClientConfiguration = serde_yaml::from_str(cfg_raw).expect("Bad client config file structure");
    client::client_mode(config).await;
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
            .possible_values(&["server", "client", "gen_cfg", "new_peer"])
            .help("Runs the program in either server or client mode"))
        .arg(Arg::with_name("config")
            .long("config")
            .required(true)
            .value_name("FILE")
            .help("The path to VPN configuration file")
            .takes_value(true))
        .arg(Arg::with_name("peer-cfg")
            .long("peer-cfg")
            .value_name("FILE")
            .help("The path to VPN peer configuration file")
            .takes_value(true))
        .arg(Arg::with_name("bind-address")
            .long("bind-address")
            .value_name("IP:PORT")
            .help("The ip:port that would be used to bind server (config)")
            .takes_value(true))
        .arg(Arg::with_name("endpoint")
            .long("endpoint")
            .value_name("IP:PORT")
            .help("The ip:port that would be used by client to connect (config)")
            .takes_value(true))
        .arg(Arg::with_name("internal-address")
            .long("internal-address")
            .value_name("IP")
            .help("The address of VPN server in it's subnet (config)")
            .takes_value(true))
        .arg(Arg::with_name("broadcast-mode")
            .long("broadcast-mode")
            .help("If set to true, then all incoming traffic with an unknown destination address will be forwarded to all peers (config)")
            .takes_value(false))
        .arg(Arg::with_name("grab-endpoint")
            .long("grab-endpoint")
            .help("If set to true, the endpoint address for peers will be grabbed from server config (config)")
            .takes_value(false))
        .arg(Arg::with_name("keepalive")
            .long("keepalive")
            .required(false)
            .value_name("SECONDS")
            .default_value("0")
            .help("Keepalive packets interval (config)")
            .takes_value(true))
        .arg(Arg::with_name("obfs-type")
            .long("obfs-type")
            .possible_values(&["dns", "icmp", "veil"])
            .takes_value(true)
            .value_name("OBFS")
            .help("Obfuscation protocol (config)"))
        .get_matches();

    let mode = matches.value_of("mode").unwrap();

    if let Some(config_path) = matches.value_of("config") {
        
        let data = fs::read(config_path);

        if data.is_err() {
            match mode {
                "gen_cfg" => generate_server_config(&matches, config_path),
                _ => error!("There is no config file.")
            }
            return;
        }

        let cfg_raw = &String::from_utf8(data.unwrap()).unwrap();

        match mode {
            "server" => init_server(cfg_raw).await,
            "client" => init_client(cfg_raw).await,
            "new_peer" => generate_peer_config(&matches, config_path, cfg_raw),
            _ => error!("There is config file already")
        }
    }
}