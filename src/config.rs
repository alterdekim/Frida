use std::{fs, io::{self, Error, Read}, net::{IpAddr, Ipv4Addr, SocketAddr}, str, sync::Arc, thread, time};
use serde_derive::Serialize;
use serde_derive::Deserialize;
use std::str::FromStr;
use x25519_dalek::{StaticSecret, PublicKey};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ServerInterface {
    pub bind_address: String,
    pub internal_address: String,
    pub private_key: String,
    pub public_key: String,
    pub broadcast_mode: bool,
    pub keepalive: u8
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ServerPeer {
    pub public_key: String,
    pub ip: Ipv4Addr
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum ObfsProtocol {
    DNSMask,
    ICMPMask,
    XOR
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ObfsConfig {
    protocol: ObfsProtocol
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ServerConfiguration {
    pub interface: ServerInterface,
    pub peers: Vec<ServerPeer>,
    pub obfs: ObfsConfig,
    pub dns: DNSConfig
}

impl ServerConfiguration {
    pub fn default(bind_address: &str, internal_address: &str, broadcast_mode: bool, keepalive: u8, obfs_type: ObfsProtocol) -> Self {
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
pub struct DNSConfig {
    enabled: bool,
    net_name: String,
    entries: Vec<DNSEntry>
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct DNSEntry {
    ip: Ipv4Addr,
    subdomain: String
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ClientInterface {
    pub private_key: String,
    pub public_key: String,
    pub address: String
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct EndpointInterface {
    pub public_key: String,
    pub endpoint: String,
    pub keepalive: u8
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ClientConfiguration {
    pub client: ClientInterface,
    pub server: EndpointInterface
}

impl ClientConfiguration {
    pub fn default(endpoint: &str, keepalive: u8, public_key: &str, internal_address: &str) -> Self {
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