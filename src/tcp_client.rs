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
use std::process::Command;
use tokio::io::AsyncReadExt;

use crate::{VpnPacket, HEADER, TAIL};

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

pub async fn client_mode(remote_addr: String) {
    info!("Starting client...");

    let mut config = tun2::Configuration::default();
    config.address("10.8.0.2");
    config.netmask("128.0.0.0");
    config.destination("0.0.0.0");
    config.name("tun0");
    config.up();

    #[cfg(target_os = "linux")]
	config.platform_config(|config| {
		config.packet_information(true);
	});

    let dev = tun2::create(&config).unwrap();
    let (mut dev_reader, mut dev_writer) = dev.split();

    #[cfg(target_os = "linux")]
    configure_routes();

    let socket = TcpStream::connect(&remote_addr).await.unwrap();
    let (mut sock_reader, mut sock_writer) = socket.into_split();

    let (tx, rx) = unbounded::<Vec<u8>>();
    let (dx, mx) = unbounded::<Vec<u8>>();

    tokio::spawn(async move {
        while let Ok(bytes) = rx.recv() {
            dev_writer.write_all(&bytes).unwrap();
        }
    });

    tokio::spawn(async move {
        let mut buf = vec![0; 4096];
        while let Ok(n) = dev_reader.read(&mut buf) {
            dx.send(buf[..n].to_vec()).unwrap();
        }
    });

    tokio::spawn(async move {
        let mut buf = vec![0; 4096];
        loop {
            if let Ok(n) = sock_reader.read(&mut buf).await {
                info!("Catch from socket");
                match bincode::deserialize::<VpnPacket>(&buf[..n]) {
                    Ok(vpn_packet) => tx.send(vpn_packet.data).unwrap(),
                    Err(error) => error!("Deserialization error {:?}", error),
                };
                //if vpn_packet.start != &HEADER || vpn_packet.end != &TAIL { error!("Bad packet"); continue; }
            }
        }
    });

    loop {
        if let Ok(bytes) = mx.recv() {
            let vpn_packet = VpnPacket::init(bytes);
            let serialized_data = bincode::serialize::<VpnPacket>(&vpn_packet).unwrap();
            //info!("Writing to sock: {:?}", serialized_data);
            sock_writer.write_all(&serialized_data).await.unwrap();
        }
    }
}