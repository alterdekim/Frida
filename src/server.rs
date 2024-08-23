use crossbeam_channel::unbounded;
use tokio::{net::UdpSocket, sync::Mutex};
use x25519_dalek::{PublicKey, StaticSecret};
use std::io::{Read, Write};
use base64::prelude::*;
use log::{error, info};
use std::sync::Arc;
use std::net::{ SocketAddr, Ipv4Addr, IpAddr };
use std::collections::HashMap;
use aes_gcm::{ aead::{Aead, AeadCore, KeyInit, OsRng},
Aes256Gcm, Nonce };

use crate::config::{ ServerConfiguration, ServerPeer};
use crate::udp::{UDPKeepAlive, UDPSerializable, UDPVpnHandshake, UDPVpnPacket};

pub async fn server_mode(server_config: ServerConfiguration) {
    info!("Starting server...");
    
    let mut config = tun2::Configuration::default();
    config.address(&server_config.interface.internal_address)
        .netmask("255.255.255.0")
        .tun_name("tun0")
        .up();

    let dev = tun2::create(&config).unwrap();
    let (mut dev_reader, mut dev_writer) = dev.split();

    let sock = UdpSocket::bind(&server_config.interface.bind_address).await.unwrap();
    let sock_rec = Arc::new(sock);
    let sock_snd = sock_rec.clone();
    let sock_hnd = sock_snd.clone();
    let addresses = Arc::new(Mutex::new(HashMap::<IpAddr, UDPeer>::new()));
    let peers = Arc::new(Mutex::new(Vec::<ServerPeer>::new()));

    let (send2tun, recv2tun) = unbounded::<Vec<u8>>();

    let (send2hnd, recv2hnd) = unbounded::<(Vec<u8>, SocketAddr)>();

    tokio::spawn(async move {
        loop {
            if let Ok(bytes) = recv2tun.recv() {
                dev_writer.write_all(&bytes).unwrap();
            }
        }
    });

    let keepalive_sec = server_config.interface.keepalive.clone();
 //   let send2hnd_cl = send2hnd.clone();
    let addrs_lcl = addresses.clone();
    if keepalive_sec > 0 {
        tokio::spawn(async move {
            let mut now = std::time::Instant::now();
            let kps = std::time::Duration::from_secs(keepalive_sec.clone().into());
            loop {
                if now.elapsed() < kps { continue; }
                now = std::time::Instant::now();
                let mut mmp = addrs_lcl.lock().await;
                mmp.values().for_each(|p| {
                    //let _ = send2hnd_cl.send((UDPKeepAlive{}.serialize(), p.addr));
                });
                drop(mmp);
            }
        });
    }

    tokio::spawn(async move {
        loop {
            if let Ok((handshake, addr)) = recv2hnd.recv() {
                let _ = sock_hnd.send_to(&handshake, addr).await;
            }
        }
    });

    let addrs_cl = addresses.clone();
    tokio::spawn(async move {
        let mut buf = vec![0; 4096];
        while let Ok(n) = dev_reader.read(&mut buf) {
            if n <= 19 { continue; }
            
            let ip = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));
            let mp = addrs_cl.lock().await;
            if let Some(peer) = mp.get(&ip) {
                
                let aes = Aes256Gcm::new(&peer.shared_secret.into());
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

                let ciphered_data = aes.encrypt(&nonce, &buf[..n]);

                if let Ok(ciphered_d) = ciphered_data {
                    let vpn_packet = UDPVpnPacket{ data: ciphered_d, nonce: nonce.to_vec()};
                    let _ = sock_snd.send_to(&vpn_packet.serialize(), peer.addr).await;
                } else {
                    error!("Traffic encryption failed.");
                }
            } else {
                // TODO: check in config is broadcast mode enabled (if not, do not send this to everyone)
                //mp.values().for_each(| peer | { sock_snd.send_to(&buf[..n], peer.addr); });
            }
            drop(mp);
        }
    });
    
    let mut buf = vec![0; 2048];
    let addrs_lp = addresses.clone();
    let peers_lp = peers.clone();

    let mut f_plp = peers_lp.lock().await;
    server_config.peers.iter().for_each(|c| f_plp.push(c.clone()));
    drop(f_plp);

    loop {
        if let Ok((len, addr)) = sock_rec.recv_from(&mut buf).await {
            let mut mp = addrs_lp.lock().await;
            let plp = peers_lp.lock().await;
            match buf.first() {
                Some(h) => {
                    match h {
                        0 => {
                            // (&buf[1..len]).to_vec()
                            let handshake = UDPVpnHandshake::deserialize(&buf);
                            info!("Got handshake! ip: {:?}; key: {:?}", handshake.request_ip, BASE64_STANDARD.encode(&handshake.public_key));
                            let skey = BASE64_STANDARD.encode(&handshake.public_key);
                            if plp.iter().any(|c| c.ip == handshake.request_ip && c.public_key == skey) {
                                let internal_ip = IpAddr::V4(handshake.request_ip);
                                info!("Accepted client");
                                let mut k = [0u8; 32];
                                for (&x, p) in handshake.public_key.iter().zip(k.iter_mut()) {
                                    *p = x;
                                }
                                let static_secret = BASE64_STANDARD.decode(&server_config.interface.private_key).unwrap();
                                let mut k1 = [0u8; 32];
                                for (&x, p) in static_secret.iter().zip(k1.iter_mut()) {
                                    *p = x;
                                }
                                let shared_secret = StaticSecret::from(k1)
                                    .diffie_hellman(&PublicKey::from(k));
                                mp.insert(internal_ip, UDPeer { addr, shared_secret: *shared_secret.as_bytes() });
                                
                                let handshake_response = UDPVpnHandshake{ public_key: BASE64_STANDARD.decode(&server_config.interface.public_key).unwrap(), request_ip: handshake.request_ip };

                                let _ = send2hnd.send((handshake_response.serialize(), addr));
                            } else {
                                info!("Bad handshake");
                                plp.iter().for_each(|c| info!("ip: {:?}; pkey: {:?}", c.ip, c.public_key));
                            }
                        }, // handshake
                        1 => {
                            let packet = UDPVpnPacket::deserialize(&(buf[..len].to_vec()));
                            mp.values().filter(| p | p.addr == addr).for_each(|p| {
                                info!("Key {:?} / nonce {:?}", &p.shared_secret, &packet.nonce);
                                let aes = Aes256Gcm::new(&p.shared_secret.into());
                                let nonce = Nonce::clone_from_slice(&packet.nonce[..]);
                                match aes.decrypt(&nonce, &packet.data[..]) {
                                    Ok(decrypted) => { let _ = send2tun.send(decrypted); },
                                    Err(error) => error!("Decryption error! {:?}", error)
                                }
                            });
                        }, // payload
                        _ => error!("Unexpected header value.")
                    }
                },
                None => error!("There is no header")
            }
            drop(plp);
            drop(mp);
        }
    }
}

struct UDPeer {
    addr: SocketAddr,
    shared_secret: [u8; 32]
}