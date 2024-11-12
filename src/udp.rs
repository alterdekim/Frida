
use std::net::Ipv4Addr;
use chrono::{Timelike, Utc};
use rand::Rng;

pub struct UDPVpnPacket {
    pub nonce: Vec<u8>, // [u8; 12]
    pub data: Vec<u8>
}

pub struct UDPKeepAlive {}

impl UDPSerializable for UDPKeepAlive {
    fn serialize(&self) -> Vec<u8> {
        let h: &[u8] = &[2];
        [h, &[Utc::now().second() as u8]].concat()
    }
}

impl UDPSerializable for UDPVpnPacket {
    fn serialize(&self) -> Vec<u8> {
        let h: &[u8] = &[1];
        [h, &self.nonce, &self.data[..]].concat()
    }
}

impl UDPVpnPacket {
    pub fn deserialize(data: &Vec<u8>) -> Self {
        UDPVpnPacket { nonce: data[1..=12].to_vec(), data: data[13..].to_vec() }
    }
}

pub struct UDPVpnRouterIP {
    pub router_ip: Ipv4Addr // [u8; 4]
}

impl UDPSerializable for UDPVpnRouterIP {
    fn serialize(&self) -> Vec<u8> {
        let h: &[u8] = &[3];
        [h, &self.router_ip.octets()].concat() // [u8; 5]
    }
}

impl UDPVpnRouterIP {
    pub fn deserialize(data: &Vec<u8>) -> Self {
        UDPVpnRouterIP { router_ip: Ipv4Addr::new(data[1], data[2], data[3], data[4]) }
    }
}

pub struct UDPVpnAskForIP {}

impl UDPVpnAskForIP {
    pub fn deserialize(data: &Vec<u8>) -> Result<UDPVpnAskForIP, ()> {
        if data.len() == 33 {
            return Ok(UDPVpnAskForIP {});
        }
        Err(())
    }
}

impl UDPSerializable for UDPVpnAskForIP {
    fn serialize(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let h: &[u8] = &[3];
        let a: [u8; 32] = rng.gen();
        [h, &a].concat()
    }
}

pub struct UDPVpnHandshake {
    pub public_key: Vec<u8>,
    pub request_ip: Ipv4Addr // [u8; 4]
}

impl UDPSerializable for UDPVpnHandshake {
    fn serialize(&self) -> Vec<u8> {
        let h: &[u8] = &[0];
        [h, &self.public_key[..], &self.request_ip.octets()].concat()
    }
}

impl UDPVpnHandshake {
    pub fn deserialize(data: &Vec<u8>) -> Self {
        UDPVpnHandshake { public_key: data[1..=32].to_vec(), request_ip: Ipv4Addr::new(data[33], data[34], data[35], data[36]) }
    }
}

pub trait UDPSerializable {
    fn serialize(&self) -> Vec<u8>;
}