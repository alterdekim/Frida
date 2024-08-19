use crossbeam_channel::{unbounded, Receiver, Sender};
use tokio::{io::AsyncWriteExt, net::{TcpListener, TcpSocket, TcpStream, UdpSocket}, sync::{mpsc, Mutex}};
use tokio::task::JoinSet;
use packet::{builder::Builder, icmp, ip, AsPacket, Packet};
use std::io::{Read, Write};
use tun2::BoxError;
use log::{error, info, LevelFilter};
use std::sync::Arc;
use std::net::{ SocketAddr, Ipv4Addr, IpAddr };
use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use std::process::Command;

use crate::{ VpnPacket, ServerConfiguration, UDPSerializable };

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
    
    loop {
        if let Ok((len, addr)) = sock_rec.recv_from(&mut buf).await {
            let mut mp = addrs_lp.lock().await;
            match buf.first() {
                Some(h) => {
                    match h {
                        0 => {
                            // (&buf[1..len]).to_vec()
                            let internal_ip = IpAddr::V4(Ipv4Addr::new(10,8,0,2));
                            info!("Got handshake");
                            mp.insert(internal_ip, UDPeer { addr });
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
            drop(mp);
        }
    }
}

struct UDPeer {
    addr: SocketAddr
}

/*struct WrappedUDP {
    sock_rec: Arc<UdpSocket>,
    sock_snd: Arc<UdpSocket>,
    addresses: Arc<Mutex<HashMap<IpAddr, UDPeer>>>
}

impl WrappedUDP {
    pub async fn new(addr: &str) -> Self {
        
        WrappedUDP { sock_rec, sock_snd, addresses }
    }

    pub async fn init(&self) {
        
    }
}*/