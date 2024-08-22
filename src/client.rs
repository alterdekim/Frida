use crossbeam_channel::{unbounded, Receiver};
use tokio::{net::UdpSocket, sync::{mpsc, Mutex}};
use tokio::task::JoinSet;
use packet::{builder::Builder, icmp, ip};
use std::io::{Read, Write};
use tun2::BoxError;
use log::{error, info, warn, LevelFilter};
use std::sync::Arc;
use std::net::{ SocketAddr, Ipv4Addr };
use std::collections::HashMap;
use std::process::Command;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce};

use crate::config::ClientConfiguration;
use crate::udp::{UDPVpnPacket, UDPVpnHandshake, UDPSerializable};

fn configure_routes() {
    let ip_output = Command::new("ip")
        .arg("addr")
        .arg("add")
        .arg("10.8.0.2/24")
        .arg("dev")
        .arg("tun0")
        .output()
        .expect("Failed to execute IP command");

    if !ip_output.status.success() {
        eprintln!("Failed to set IP: {}", String::from_utf8_lossy(&ip_output.stderr));
        return;
    }

    let link_output = Command::new("ip")
        .arg("link")
        .arg("set")
        .arg("up")
        .arg("dev")
        .arg("tun0")
        .output()
        .expect("Failed to execute IP LINK command");

    if !link_output.status.success() {
        eprintln!("Failed to set link up: {}", String::from_utf8_lossy(&link_output.stderr));
        return;
    }

    let route_output = Command::new("ip")
        .arg("route")
        .arg("add")
        .arg("0.0.0.0/0")
        .arg("via")
        .arg("10.8.0.1")
        .arg("dev")
        .arg("tun0")
        .output()
        .expect("Failed to execute IP ROUTE command");

    if !route_output.status.success() {
        eprintln!("Failed to set route: {}", String::from_utf8_lossy(&route_output.stderr));
    }
}

pub async fn client_mode(client_config: ClientConfiguration) {
    info!("Starting client...");

    let mut config = tun2::Configuration::default();
    config.address(&client_config.client.address)
        .netmask("128.0.0.0")
        .destination("0.0.0.0")
        .tun_name("tun0")
        .up();

    #[cfg(target_os = "linux")]
	config.platform_config(|config| {
		config.packet_information(true);
	});

    let dev = tun2::create(&config).unwrap();
    let (mut dev_reader, mut dev_writer) = dev.split();

    #[cfg(target_os = "linux")]
    configure_routes();

    let sock = UdpSocket::bind("0.0.0.0:59611").await.unwrap();
    sock.connect(&client_config.server.endpoint).await.unwrap();

    let sock_rec = Arc::new(sock);
    let sock_snd = sock_rec.clone();

    let (tx, rx) = unbounded::<Vec<u8>>();
    let (dx, mx) = unbounded::<Vec<u8>>();

    let cipher_shared = Arc::new(Mutex::new(None));

    tokio::spawn(async move {
        while let Ok(bytes) = rx.recv() {
            info!("Write to tun {:?}", hex::encode(&bytes));
            dev_writer.write_all(&bytes).unwrap();
        }
    });

    tokio::spawn(async move {
        let mut buf = vec![0; 8192];
        while let Ok(n) = dev_reader.read(&mut buf) {
            dx.send(buf[..n].to_vec()).unwrap();
        }
    });

    let priv_key = base64::decode(client_config.client.private_key).unwrap();
    
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
                                // Aes256Gcm::new(shared_secret.as_bytes().into());
                            }, // handshake
                            1 => {
                                let wrapped_packet = UDPVpnPacket::deserialize(&(buf[..l].to_vec()));
                                if s_cipher.is_some() {
                                    let aes = Aes256Gcm::new(s_cipher.as_ref().unwrap().as_bytes().into());
                                    let nonce = Nonce::clone_from_slice(&wrapped_packet.nonce);
                                    match aes.decrypt(&nonce, &wrapped_packet.data[..]) {
                                        Ok(decrypted) => { tx.send(decrypted); },
                                        Err(error) => error!("Decryption error! {:?}", error)
                                    }
                                } else {
                                    warn!("There is no static_secret");
                                }
                            }, // payload
                            _ => error!("Unexpected header value.")
                        }
                    },
                    None => error!("There is no header.")
                }
                drop(s_cipher);
            }
        }
    });

    let pkey = base64::decode(client_config.client.public_key).unwrap();
    let handshake = UDPVpnHandshake{ public_key: pkey, request_ip: client_config.client.address.parse::<Ipv4Addr>().unwrap() };
    sock_snd.send(&handshake.serialize()).await.unwrap();

    let s_cipher = cipher_shared.clone();
    loop {
        if let Ok(bytes) = mx.recv() {
            let s_c = s_cipher.lock().await;
            
            if s_c.is_some() {
                let aes = Aes256Gcm::new(s_c.as_ref().unwrap().as_bytes().into());
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                info!("Key {:?} / nonce {:?}", s_c.as_ref().unwrap().as_bytes(), &nonce.bytes());
                let ciphered_data = aes.encrypt(&nonce, &bytes[..]);
                
                if let Ok(ciphered_d) = ciphered_data {
                    let vpn_packet = UDPVpnPacket{ data: ciphered_d, nonce: nonce.to_vec()};
                    let serialized_data = vpn_packet.serialize();
                    info!("Writing to sock: {:?}", serialized_data);
                    sock_snd.send(&serialized_data).await.unwrap();
                } else {
                    error!("Socket encryption failed.");
                }
            } else {
                warn!("There is no shared_secret in main loop");
            }
        }
    }
}