//use crossbeam_channel::unbounded;
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::{net::UdpSocket, sync::Mutex, time};
use x25519_dalek::{PublicKey, StaticSecret};
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

    let dev = tun2::create_as_async(&config).unwrap();
    let (mut dev_writer, mut dev_reader) = dev.into_framed().split();

    let sock = UdpSocket::bind(&server_config.interface.bind_address).await.unwrap();
    let sock_rec = Arc::new(sock);
    let sock_hnd = sock_rec.clone();
    let addresses = Arc::new(Mutex::new(HashMap::<IpAddr, UDPeer>::new()));
    let peers = Arc::new(Mutex::new(Vec::<ServerPeer>::new()));

    let (send2tun, mut recv2tun) = mpsc::unbounded_channel::<Vec<u8>>(); // unbounded::<Vec<u8>>();

    let (send2hnd, mut recv2hnd) = mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>(); // unbounded::<(Vec<u8>, SocketAddr)>();

    let tun_writer_task = tokio::spawn(async move {
        loop {
            if let Some(bytes) = recv2tun.recv().await {
                info!("Sent to tun!");
                let _ = dev_writer.send(bytes).await;
            }
        }
    });

    let keepalive_sec = server_config.interface.keepalive.clone();
    let send2hnd_cl = send2hnd.clone();
    let addrs_lcl = addresses.clone();

    let alive_task = tokio::spawn(async move {
        let kp_sc = keepalive_sec.clone();
        if kp_sc <= 0 { return; }
        loop {
            time::sleep(time::Duration::from_secs(kp_sc.into())).await;
            let mmp = addrs_lcl.lock().await;
            mmp.values().for_each(|p| {
                let _ = send2hnd_cl.send((UDPKeepAlive{}.serialize(), p.addr));
            });
            drop(mmp);
        }
    });

    let sock_writer_task = tokio::spawn(async move {
        loop {
            if let Some((handshake, addr)) = recv2hnd.recv().await {
                info!("I SENT THAT STUFF");
                let _ = sock_hnd.send_to(&handshake, addr).await;
            }
        }
    });

    let addrs_cl = addresses.clone();
    let send2hnd_sr = send2hnd.clone();
    let tun_reader_task = tokio::spawn(async move {
        while let Some(Ok(buf)) = dev_reader.next().await {
            if buf.len() <= 19 { continue; }
            
            let ip = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));
            let mp = addrs_cl.lock().await;
            if let Some(peer) = mp.get(&ip) {
                
                let aes = Aes256Gcm::new(&peer.shared_secret.into());
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

                let ciphered_data = aes.encrypt(&nonce, &buf[..]);

                if let Ok(ciphered_d) = ciphered_data {
                    let vpn_packet = UDPVpnPacket{ data: ciphered_d, nonce: nonce.to_vec()};
                    let _ = send2hnd_sr.send((vpn_packet.serialize(), peer.addr));
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
    
    let addrs_lp = addresses.clone();
    let peers_lp = peers.clone();

    let mut f_plp = peers_lp.lock().await;
    server_config.peers.iter().for_each(|c| f_plp.push(c.clone()));
    drop(f_plp);

    let send2hnd_ssr = send2hnd.clone();

    let sock_reader_task = tokio::spawn(async move {
        let mut buf = vec![0; 2048];
        loop {
            if let Ok((len, addr)) = sock_rec.recv_from(&mut buf).await {
                info!("There is packet!");
                let mut mp = addrs_lp.lock().await;
                let plp = peers_lp.lock().await;
                match buf.first() {
                    Some(h) => {
                        match h {
                            0 => {
                                let handshake = UDPVpnHandshake::deserialize(&buf);
                                info!("Got handshake from {:?}", handshake.request_ip);
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
    
                                    let _ = send2hnd_ssr.send((handshake_response.serialize(), addr));
                                } else {
                                    info!("Bad handshake");
                                    //plp.iter().for_each(|c| info!("ip: {:?}; pkey: {:?}", c.ip, c.public_key));
                                }
                            }, // handshake
                            1 => {
                                let packet = UDPVpnPacket::deserialize(&(buf[..len].to_vec()));
                                mp.values().filter(| p | p.addr == addr).for_each(|p| {
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
    });
    
    tokio::join!(tun_reader_task, sock_reader_task, sock_writer_task, tun_writer_task, alive_task);
}

struct UDPeer {
    addr: SocketAddr,
    shared_secret: [u8; 32]
}