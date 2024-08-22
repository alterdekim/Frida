use tokio::{net::UdpSocket, sync::mpsc};
use std::{fs, io::{self, Error, Read}, net::{IpAddr, Ipv4Addr, SocketAddr}, str, sync::Arc, thread, time};
use std::process::Command;
use clap::{App, Arg, ArgMatches};
use env_logger::Builder;
use log::{error, info, warn, LevelFilter};
use serde_derive::Serialize;
use serde_derive::Deserialize;
use std::str::FromStr;
use x25519_dalek::{StaticSecret, PublicKey};
use rand::{rngs::StdRng, SeedableRng};
use crate::config::{ ServerConfiguration, ClientConfiguration, ObfsConfig, ObfsProtocol, ServerPeer };


mod server;
mod client;
mod udp;
mod config;


fn generate_server_config(matches: &ArgMatches, config_path: &str) {
    let bind_address = matches.value_of("bind-address").expect("No bind address specified");
    let internal_address = matches.value_of("internal-address").expect("No internal address specified");
    let broadcast_mode = matches.value_of("broadcast-mode").is_some();
    let keepalive: u8 = matches.value_of("keepalive").unwrap().parse().expect("Keepalive argument should be a number");
    let obfs_type = match matches.value_of("obfs-type").expect("Obfs type should be specified") {
        "dns" => ObfsProtocol::DNSMask,
        "icmp" => ObfsProtocol::ICMPMask,
        _ => ObfsProtocol::XOR
    };

    fs::write(config_path, serde_yaml::to_string(&ServerConfiguration::default(bind_address, internal_address, broadcast_mode, keepalive, obfs_type)).unwrap());
}

fn generate_peer_config(matches: &ArgMatches, config_path: &str, cfg_raw: &String) {
    let keepalive: u8 = matches.value_of("keepalive").unwrap().parse().expect("Keepalive argument should be a number");
    let grab_endpoint = matches.value_of("grab-endpoint").is_some();
    let endpoint = matches.value_of("endpoint").or(Some("0.0.0.0:0")).unwrap();
    let peer_cfg = matches.value_of("peer-cfg").expect("No peer cfg path specified");

    let mut config: ServerConfiguration = serde_yaml::from_str(cfg_raw).expect("Bad server config file structure");

    let prs = &mut config.peers[..];
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

    let matches = App::new("Frida")
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
            .possible_values(&["dns", "icmp", "xor"])
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