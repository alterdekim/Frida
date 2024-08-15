use crossbeam_channel::{unbounded, Receiver};
use tokio::{io::AsyncWriteExt, net::{TcpListener, TcpSocket, TcpStream}, sync::{mpsc, Mutex}};
use tokio::task::JoinSet;
use packet::{builder::Builder, icmp, ip, AsPacket, Packet};
use std::io::{Read, Write};
use tun2::BoxError;
use log::{error, info, LevelFilter};
use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use std::process::Command;

use crate::VpnPacket;

pub async fn server_mode(bind_addr: String) {
    info!("Starting server...");
    
    let mut config = tun2::Configuration::default();
    config.address("10.8.0.1");
    config.netmask("255.255.255.0");
    config.tun_name("tun0");
    config.up();

   /*  let mut route_output = Command::new("route")
        .arg("add")
        .arg("0.0.0.0")
        .arg("mask")
        .arg("128.0.0.0")
        .arg("0.0.0.0")
        .output()
        .expect("Failed to execute IP ROUTE 1");

    if !route_output.status.success() {
        error!("Failed to set route: {}", String::from_utf8_lossy(&route_output.stderr));
    }

    route_output = Command::new("route")
        .arg("add")
        .arg("10.8.0.1")
        .arg("mask")
        .arg("255.255.255.255")
        .arg("0.0.0.0")
        .output()
        .expect("Failed to execute IP ROUTE 2");

    if !route_output.status.success() {
        error!("Failed to set route: {}", String::from_utf8_lossy(&route_output.stderr));
    }

    route_output = Command::new("route")
        .arg("add")
        .arg("127.255.255.255")
        .arg("mask")
        .arg("255.255.255.255")
        .arg("0.0.0.0")
        .output()
        .expect("Failed to execute IP ROUTE 3");

    if !route_output.status.success() {
        error!("Failed to set route: {}", String::from_utf8_lossy(&route_output.stderr));
    }

    route_output = Command::new("route")
        .arg("add")
        .arg("128.0.0.0")
        .arg("mask")
        .arg("128.0.0.0")
        .arg("0.0.0.0")
        .output()
        .expect("Failed to execute IP ROUTE 4");

    if !route_output.status.success() {
        error!("Failed to set route: {}", String::from_utf8_lossy(&route_output.stderr));
    }*/

    #[cfg(target_os = "linux")]
	config.platform_config(|config| {
		config.packet_information(true);
	});

    let dev = tun2::create(&config).unwrap();
    let (mut dev_reader, mut dev_writer) = dev.split();

    let (tx, rx) = unbounded::<Vec<u8>>();
    let (dx, mx) = unbounded::<Vec<u8>>();

    tokio::spawn(async move {
        while let Ok(mut bytes) = rx.recv() {
            info!("Got packet");
            //info!("Source ip: {:?}", &bytes[12..=15]);
            //bytes[12] = 192;
            //bytes[13] = 168;
            //bytes[14] = 0;
            //bytes[15] = 5;
            dev_writer.write_all(&bytes).unwrap();
        }
    });

    tokio::spawn(async move {
        let mut buf = vec![0; 4096];
        while let Ok(n) = dev_reader.read(&mut buf) {
            dx.send(buf[..n].to_vec()).unwrap();
        }
    });

    let listener = TcpListener::bind(&bind_addr).await.unwrap();

    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (mut sock_reader, mut sock_writer) = socket.into_split();
        let thread_tx = tx.clone();
        let thread_mx = mx.clone();

        tokio::spawn(async move {
            loop {
                if let Ok(bytes) = thread_mx.recv() {
                    let vpn_packet = VpnPacket{ data: bytes };
                    let serialized_data = vpn_packet.serialize();
                    sock_writer.write_all(&serialized_data).await.unwrap();
                    //info!("Wrote to sock: {:?}", serialized_data);
                }
            }
        });

        tokio::spawn(async move {
            let mut buf = vec![0; 4096];
            loop {
                if let Ok(l) = sock_reader.read_u64().await {
                    buf = vec![0; l.try_into().unwrap()];
                    if let Ok(n) = sock_reader.read(&mut buf).await {
                        //info!("Catched from sock: {:?}", &buf[..n]);
                        match VpnPacket::deserialize((&buf[..n]).to_vec()) {
                            Ok(vpn_packet) => thread_tx.send(vpn_packet.data).unwrap(),
                            Err(error) => error!("Deserializing error {:?}", error),
                        };
                        //if vpn_packet.start != &HEADER || vpn_packet.end != &TAIL { error!("Bad packet"); continue; }
                    }
                }
            }
        });
    }
}