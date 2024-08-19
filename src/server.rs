use crossbeam_channel::{unbounded, Receiver, Sender};
use tokio::{io::AsyncWriteExt, net::{TcpListener, TcpSocket, TcpStream, UdpSocket}, sync::{mpsc, Mutex}};
use tokio::task::JoinSet;
use packet::{builder::Builder, icmp, ip, AsPacket, Packet};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use std::io::{Read, Write};
use tun2::BoxError;
use log::{error, info, LevelFilter};
use std::sync::Arc;
use std::net::{ SocketAddr, Ipv4Addr, IpAddr };
use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use std::process::Command;

use crate::{ ServerConfiguration, ServerPeer, UDPSerializable, UDPVpnHandshake, VpnPacket };

pub async fn server_mode(server_config: ServerConfiguration) {
    info!("Starting server...");
    
    let mut config = tun2::Configuration::default();
    config.address(&server_config.interface.internal_address)
        .netmask("255.255.255.0")
        .tun_name("tun0")
        .up();

    #[cfg(target_os = "linux")]
	config.platform_config(|config| {
		config.packet_information(true);
	});

    let dev = tun2::create(&config).unwrap();
    let (mut dev_reader, mut dev_writer) = dev.split();

    let sock = UdpSocket::bind(&server_config.interface.bind_address).await.unwrap();
    let sock_rec = Arc::new(sock);
    let sock_snd = sock_rec.clone();
    let addresses = Arc::new(Mutex::new(HashMap::<IpAddr, UDPeer>::new()));
    let peers = Arc::new(Mutex::new(Vec::<ServerPeer>::new()));

    let (send2tun, recv2tun) = unbounded::<Vec<u8>>();

    tokio::spawn(async move {
        loop {
            if let Ok(bytes) = recv2tun.recv() {
                dev_writer.write_all(&bytes).unwrap();
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
                sock_snd.send_to(&buf[..n], peer.addr).await;
            } else {
                // TODO: check in config is broadcast mode enabled (if not, do not send this to everyone)
                mp.values().for_each(| peer | { sock_snd.send_to(&buf[..n], peer.addr); });
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
            let mut plp = peers_lp.lock().await;
            match buf.first() {
                Some(h) => {
                    match h {
                        0 => {
                            // (&buf[1..len]).to_vec()
                            let handshake = UDPVpnHandshake::deserialize(&buf);
                            info!("Got handshake! ip: {:?}; key: {:?}", handshake.request_ip, base64::encode(&handshake.public_key));
                            let skey = base64::encode(&handshake.public_key);
                            if plp.iter().any(|c| c.ip == handshake.request_ip && c.public_key == skey) {
                                let internal_ip = IpAddr::V4(handshake.request_ip);
                                info!("Accepted client");
                                let mut k = [0u8; 32];
                                for (&x, p) in handshake.public_key.iter().zip(k.iter_mut()) {
                                    *p = x;
                                }
                                let static_secret = base64::decode(&server_config.interface.private_key).unwrap();
                                let mut k1 = [0u8; 32];
                                for (&x, p) in static_secret.iter().zip(k1.iter_mut()) {
                                    *p = x;
                                }
                                let shared_secret = StaticSecret::from(k1)
                                    .diffie_hellman(&PublicKey::from(k));
                                mp.insert(internal_ip, UDPeer { addr, shared_secret });
                            } else {
                                info!("Bad handshake");
                                plp.iter().for_each(|c| info!("ip: {:?}; pkey: {:?}", c.ip, c.public_key));
                            }
                        }, // handshake
                        1 => {
                            if mp.values().any(| p | p.addr == addr) {
                                send2tun.send((&buf[1..len]).to_vec());
                            }
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
    shared_secret: SharedSecret
}