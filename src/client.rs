use crossbeam_channel::unbounded;
use socket2::SockAddr;
use tokio::{net::UdpSocket, sync::{Mutex, mpsc}, io::{BufReader, BufWriter, AsyncWriteExt, AsyncReadExt}, fs::File};
use tokio_util::sync::CancellationToken;
use std::{io::{Read, Write}, net::SocketAddr};
use base64::prelude::*;
use log::{error, info, warn};
use std::sync::Arc;
use std::net::Ipv4Addr;
use x25519_dalek::{PublicKey, StaticSecret};
use std::{ process::Command, os::unix::io::FromRawFd};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce};

use crate::config::ClientConfiguration;
use crate::udp::{UDPVpnPacket, UDPVpnHandshake, UDPSerializable};
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;

fn configure_routes(endpoint_ip: &str, s_interface: Option<String>) {
    let interfaces = NetworkInterface::show().unwrap();

    let net_inter = interfaces.iter()
        .filter(|i| !i.addr.iter().any(|b| b.ip().to_string() == "127.0.0.1" || b.ip().to_string() == "::1") )
        .min_by(|x, y| x.index.cmp(&y.index))
        .unwrap();

    let inter_name = if s_interface.is_some() { s_interface.unwrap() } else { net_inter.name };

    info!("Main network interface: {:?}", inter_name);

    /*let mut ip_output = Command::new("sudo")
        .arg("ip")
        .arg("route")
        .arg("del")
        .arg("default")
        .output()
        .expect("Failed to delete default gateway.");

    if !ip_output.status.success() {
        error!("Failed to delete default gateway: {:?}", String::from_utf8_lossy(&ip_output.stderr));
    }*/

    let mut ip_output = Command::new("sudo")
        .arg("ip")
        .arg("-4")
        .arg("route")
        .arg("add")
        .arg("0.0.0.0/0")
        .arg("dev")
        .arg("tun0")
        .output()
        .expect("Failed to execute ip route command.");

    if !ip_output.status.success() {
        error!("Failed to route all traffic: {:?}", String::from_utf8_lossy(&ip_output.stderr));
    }

    ip_output = Command::new("sudo")
        .arg("ip")
        .arg("route")
        .arg("add")
        .arg(endpoint_ip.to_owned()+"/32")
        .arg("via")
        .arg("192.168.0.1")
        .arg("dev")
        .arg(inter_name)
        .output()
        .expect("Failed to make exception for vpns endpoint.");

    if !ip_output.status.success() {
        error!("Failed to forward packets: {:?}", String::from_utf8_lossy(&ip_output.stderr));
    }
}

/*
s_interface: Option<&str>
let s_a: SocketAddr = client_config.server.endpoint.parse().unwrap();
#[cfg(target_os = "linux")]
configure_routes(&s_a.ip().to_string(), s_interface);
*/

/*
What the fuck I want to implement?
I need to make abstract class VPNClient which should be extended by several others:
AndroidClient
DesktopClient

Both of child classes should trigger the same "core vpn client" module

*/

pub struct AndroidClient {
    client_config: ClientConfiguration,
    fd: i32,
    close_token: CancellationToken
}

pub struct DesktopClient {
    client_config: ClientConfiguration,
    s_interface: Option<String>
}

impl VpnClient for AndroidClient {
    async fn start(&self) {
        info!("FD: {:?}", &self.fd);
        let mut dev = unsafe { File::from_raw_fd(self.fd) };
        let mut dev1 = unsafe { File::from_raw_fd(self.fd) };
        let mut dev_reader = BufReader::new(dev);
        let mut dev_writer = BufWriter::new(dev1);
        let client = CoreVpnClient{client_config: self.client_config, dev_reader, dev_writer, close_token: self.close_token};
        client.start().await;
    }
}

impl VpnClient for DesktopClient {
    async fn start(&self) {
        info!("s_interface: {:?}", &self.s_interface);
        let mut config = tun2::Configuration::default();
        config.address(&self.client_config.client.address)
            .netmask("255.255.255.255")
            .destination("10.66.66.1")
            .tun_name("tun0")
            .up();
    
        let dev = tun2::create(&config).unwrap();
        let (mut dev_reader, mut dev_writer) = dev.split();
        let client = CoreVpnClient{ client_config: self.client_config, dev_reader, dev_writer, close_token: tokio_util::sync::CancellationToken::new()};
        client.start().await;
    }
}

pub trait VpnClient {
    async fn start(&self);
}

struct CoreVpnClient {
    client_config: ClientConfiguration,
    dev_reader: Reader,
    dev_writer: Writer,
    close_token: CancellationToken
}

impl CoreVpnClient {
    pub async fn start(&self) {
        info!("Starting client...");

        let dr_cancel: CancellationToken = CancellationToken::new();
        let sr_cancel: CancellationToken = CancellationToken::new();
    
        let sock = UdpSocket::bind("0.0.0.0:25565").await.unwrap();
        sock.connect(&self.client_config.server.endpoint).await.unwrap();
    
        let sock_rec = Arc::new(sock);
        let sock_snd = sock_rec.clone();
    
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (dx, mut mx) = mpsc::unbounded_channel::<Vec<u8>>();
    
        let cipher_shared: Arc<Mutex<Option<x25519_dalek::SharedSecret>>> = Arc::new(Mutex::new(None));
    
        let dr_cc = dr_cancel.clone();
        let dev_read_task = tokio::spawn(async move {
            let mut buf = vec![0; 1400]; // mtu
            loop {
                tokio::select! {
                    _ = dr_cc.cancelled() => {
                        info!("Cancellation token has been thrown dev_read_task");
                        return;
                    }
                    rr = self.dev_reader.read(&mut buf) => {
                        if let Ok(n) = rr {
                            info!("Read from tun."); // hex::encode(&buf[..n])
                            dx.send(buf[..n].to_vec()).unwrap();
                        }
                    }
                };
            }
        });
    
        let priv_key = BASE64_STANDARD.decode(self.client_config.client.private_key).unwrap();
        
        let cipher_shared_clone = cipher_shared.clone();
        let sr_cc = sr_cancel.clone();
        let sock_read_task = tokio::spawn(async move {
            let mut buf = vec![0; 4096];
    
            loop {
                tokio::select! {
                    _ = sr_cc.cancelled() => {
                        info!("Cancellation token has been thrown sock_read_task");
                        return;
                    }
                    rr = sock_rec.recv(&mut buf) => {
                        if let Ok(l) = rr {
                            info!("Read from socket");
                            let mut s_cipher = cipher_shared_clone.lock().await;
                            match buf.first() {
                                Some(h) => {
                                    match h {
                                        0 => {
                                            let handshake = UDPVpnHandshake::deserialize(&(buf[..l].to_vec()));
                                            let mut k = [0u8; 32];
                                            for (&x, p) in handshake.public_key.iter().zip(k.iter_mut()) {
                                                *p = x;
                                            }
                                            let mut k1 = [0u8; 32];
                                            for (&x, p) in priv_key.iter().zip(k1.iter_mut()) {
                                                *p = x;
                                            }
                                            *s_cipher = Some(StaticSecret::from(k1)
                                                .diffie_hellman(&PublicKey::from(k)));
                                        }, // handshake
                                        1 => {
                                            let wrapped_packet = UDPVpnPacket::deserialize(&(buf[..l].to_vec()));
                                            if s_cipher.is_some() {
                                                let aes = Aes256Gcm::new(s_cipher.as_ref().unwrap().as_bytes().into());
                                                let nonce = Nonce::clone_from_slice(&wrapped_packet.nonce);
                                                match aes.decrypt(&nonce, &wrapped_packet.data[..]) {
                                                    Ok(decrypted) => { let _ = tx.send(decrypted); },
                                                    Err(error) => { error!("Decryption error! {:?}", error); }
                                                }
                                            } else {
                                                warn!("There is no static_secret");
                                            }
                                        }, // payload
                                        2 => { info!("Got keepalive packet"); },
                                        _ => { error!("Unexpected header value."); }
                                    }
                                },
                                None => { error!("There is no header."); }
                            }
                            drop(s_cipher);
                        }
                    }
                };
            }
        });
    
        let pkey = BASE64_STANDARD.decode(self.client_config.client.public_key).unwrap();
        let handshake = UDPVpnHandshake{ public_key: pkey, request_ip: self.client_config.client.address.parse::<Ipv4Addr>().unwrap() };
        let mut nz = 0;
        while nz < 25 {
            sock_snd.send(&handshake.serialize()).await.unwrap();
            nz += 1
        }
        //sock_snd.send(&handshake.serialize()).await.unwrap();
    
        let s_cipher = cipher_shared.clone();
        loop {
            tokio::select! {
                _ = self.close_token.cancelled() => {
                    info!("Cancellation token has been thrown");
                    sr_cancel.cancel();
                    dr_cancel.cancel();
                    return;
                }
                rr = rx.recv() => {
                    if let Some(bytes) = rr {
                        info!("Write to tun.");
                        if let Err(e) = self.dev_writer.write_all(&bytes).await {
                            error!("Writing error: {:?}", e);
                        }
                        if let Err(e) = self.dev_writer.flush().await {
                            error!("Flushing error: {:?}", e);
                        }
                    }
                }
                rr2 = mx.recv() => {
                    if let Some(bytes) = rr2 {
                        let s_c = s_cipher.lock().await;
                        
                        if s_c.is_some() {
                            let aes = Aes256Gcm::new(s_c.as_ref().unwrap().as_bytes().into());
                            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                            let ciphered_data = aes.encrypt(&nonce, &bytes[..]);
                            
                            if let Ok(ciphered_d) = ciphered_data {
                                let vpn_packet = UDPVpnPacket{ data: ciphered_d, nonce: nonce.to_vec()};
                                let serialized_data = vpn_packet.serialize();
                                info!("Write to socket");
                                sock_snd.send(&serialized_data).await.unwrap();
                            } else {
                                error!("Socket encryption failed.");
                            }
                        } else {
                            error!("There is no shared_secret in main loop");
                        }
                    }
                }
            };
        }
    }
}

/*pub async fn client_mode(client_config: ClientConfiguration, s_interface: Option<&str>) {
    info!("Starting client...");
    info!("s_interface: {:?}", s_interface);

    let sock = UdpSocket::bind("0.0.0.0:25565").await.unwrap();
    sock.connect(&client_config.server.endpoint).await.unwrap();



    let sock_rec = Arc::new(sock);
    let sock_snd = sock_rec.clone();

    let (tx, rx) = unbounded::<Vec<u8>>();
    let (dx, mx) = unbounded::<Vec<u8>>();

    let cipher_shared = Arc::new(Mutex::new(None));

    tokio::spawn(async move {
        while let Ok(bytes) = rx.recv() {
            //info!("Write to tun {:?}", hex::encode(&bytes));
            dev_writer.write_all(&bytes).unwrap();
        }
    });

    tokio::spawn(async move {
        let mut buf = vec![0; 8192];
        while let Ok(n) = dev_reader.read(&mut buf) {
            dx.send(buf[..n].to_vec()).unwrap();
        }
    });

    

    let priv_key = BASE64_STANDARD.decode(client_config.client.private_key).unwrap();
    
    let cipher_shared_clone = cipher_shared.clone();
    tokio::spawn(async move {
        let mut buf = vec![0; 4096];

        loop {
            if let Ok(l) = sock_rec.recv(&mut buf).await {
                let mut s_cipher = cipher_shared_clone.lock().await;
                match buf.first() {
                    Some(h) => {
                        match h {
                            0 => {
                                let handshake = UDPVpnHandshake::deserialize(&(buf[..l].to_vec()));
                                let mut k = [0u8; 32];
                                for (&x, p) in handshake.public_key.iter().zip(k.iter_mut()) {
                                    *p = x;
                                }
                                let mut k1 = [0u8; 32];
                                for (&x, p) in priv_key.iter().zip(k1.iter_mut()) {
                                    *p = x;
                                }
                                *s_cipher = Some(StaticSecret::from(k1)
                                    .diffie_hellman(&PublicKey::from(k)));
                            }, // handshake
                            1 => {
                                let wrapped_packet = UDPVpnPacket::deserialize(&(buf[..l].to_vec()));
                                if s_cipher.is_some() {
                                    let aes = Aes256Gcm::new(s_cipher.as_ref().unwrap().as_bytes().into());
                                    let nonce = Nonce::clone_from_slice(&wrapped_packet.nonce);
                                    match aes.decrypt(&nonce, &wrapped_packet.data[..]) {
                                        Ok(decrypted) => { let _ = tx.send(decrypted); },
                                        Err(error) => error!("Decryption error! {:?}", error)
                                    }
                                } else {
                                    warn!("There is no static_secret");
                                }
                            }, // payload
                            2 => info!("Got keepalive packet"),
                            _ => error!("Unexpected header value.")
                        }
                    },
                    None => error!("There is no header.")
                }
                drop(s_cipher);
            }
        }
    });

    let pkey = BASE64_STANDARD.decode(client_config.client.public_key).unwrap();
    let handshake = UDPVpnHandshake{ public_key: pkey, request_ip: client_config.client.address.parse::<Ipv4Addr>().unwrap() };
    let mut nz = 0;
    while nz < 25 {
        sock_snd.send(&handshake.serialize()).await.unwrap();
        nz += 1
    }
    //sock_snd.send(&handshake.serialize()).await.unwrap();

    let s_cipher = cipher_shared.clone();
    loop {
        if let Ok(bytes) = mx.recv() {
            let s_c = s_cipher.lock().await;
            
            if s_c.is_some() {
                let aes = Aes256Gcm::new(s_c.as_ref().unwrap().as_bytes().into());
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                let ciphered_data = aes.encrypt(&nonce, &bytes[..]);
                
                if let Ok(ciphered_d) = ciphered_data {
                    let vpn_packet = UDPVpnPacket{ data: ciphered_d, nonce: nonce.to_vec()};
                    let serialized_data = vpn_packet.serialize();
                    sock_snd.send(&serialized_data).await.unwrap();
                } else {
                    error!("Socket encryption failed.");
                }
            } else {
                warn!("There is no shared_secret in main loop");
            }
        }
    }
}*/