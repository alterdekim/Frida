use crossbeam_channel::{unbounded, Receiver};
use tokio::{io::AsyncWriteExt, net::{TcpListener, TcpSocket, TcpStream}, sync::{mpsc, Mutex}};
use tokio::task::JoinSet;
use packet::{builder::Builder, icmp, ip, Packet};
use std::io::{Read, Write};
use tun2::BoxError;
use log::{error, info, LevelFilter};
use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::HashMap;
use tokio::io::AsyncReadExt;

use crate::VpnPacket;

pub async fn server_mode() {
    info!("Starting server...");
    
    let mut config = tun2::Configuration::default();
    config.address("10.8.0.1");
    config.tun_name("tun0");
    config.up();

    #[cfg(target_os = "linux")]
	config.platform_config(|config| {
		config.packet_information(true);
	});

    let dev = tun2::create(&config).unwrap();
    let (mut dev_reader, mut dev_writer) = dev.split();

    let (tx, rx) = unbounded::<Vec<u8>>();
    let (dx, mx) = unbounded::<Vec<u8>>();

    tokio::spawn(async move {
        while let Ok(bytes) = rx.recv() {
            dev_writer.write(&bytes).unwrap();
        }
    });

    tokio::spawn(async move {
        let mut buf = vec![0; 2048];
        while let Ok(n) = dev_reader.read(&mut buf) {
            dx.send(buf[..n].to_vec()).unwrap();
        }
    });

    let listener = TcpListener::bind("192.168.0.5:8879".parse::<SocketAddr>().unwrap()).await.unwrap();

    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (mut sock_reader, mut sock_writer) = socket.into_split();
        let thread_tx = tx.clone();
        let thread_mx = mx.clone();

        tokio::spawn(async move {
            loop {
                if let Ok(bytes) = thread_mx.recv() {
                    let vpn_packet = VpnPacket::init(bytes);
                    let serialized_data = bincode::serialize(&vpn_packet).unwrap();
                    sock_writer.write_all(&serialized_data).await.unwrap();
                    info!("Wrote to sock: {:?}", serialized_data);
                }
            }
        });

        tokio::spawn(async move {
            let mut buf = vec![0; 2048];
            loop {
                if let Ok(n) = sock_reader.read(&mut buf).await {
                    info!("Catched from sock: {:?}", &buf[..n]);
                    let vpn_packet: VpnPacket = bincode::deserialize(&buf[..n]).unwrap();
                    thread_tx.send(vpn_packet.data).unwrap();
                }
            }
        });
    }
}