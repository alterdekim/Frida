use std::process::Command;
use clap::{App, Arg};
use env_logger::Builder;
use tokio::{net::UdpSocket, sync::{mpsc, Mutex}};
use tokio::task::JoinSet;
use std::io::{self, Read, Write};
use std::sync::mpsc::Receiver;
use tun2::BoxError;
use log::{error, info, LevelFilter};
use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::HashMap;

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

pub async fn client_mode(remote_addr: &str) -> io::Result<()> {
    info!("Starting client...");

    let mut config = tun2::Configuration::default();
    config.address("10.8.0.2");
    config.netmask("128.0.0.0");
    config.destination("0.0.0.0");
    config.name("tun0");
    config.up();

    #[cfg(target_os = "linux")]
	config.platform(|config| {
		config.packet_information(true);
	});

    let dev = tun2::create(&config)?;
    let (mut reader, mut writer) = dev.split();

    #[cfg(target_os = "linux")]
    configure_routes();

    let sock = UdpSocket::bind("0.0.0.0:59611").await?;
    sock.connect(remote_addr).await?;
    let r = Arc::new(sock);
    let s = r.clone();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1_000);
    
    let mut set = JoinSet::new();

    set.spawn(async move {
        let mut buf = [0; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(size) => {
                    let pkt = &buf[..size];
                    use std::io::{Error, ErrorKind::Other};
                    tx.send(pkt.to_vec()).await.unwrap();
                    info!("Wrote to sock");
                }
                Err(error) => error!("Error with reading from tun")
            }
            ()
        }
    });

    set.spawn(async move {
        while let Some(bytes) = rx.recv().await {
            let len = s.send(&bytes).await.unwrap();
            println!("{:?} bytes sent", len);
        }
    });

    set.spawn(async move {
        let mut buf = [0; 1024];
        loop {
            match r.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    println!("{:?} bytes received from {:?}", len, addr);
                    writer.write_all(&buf[..len]);
                    info!("Wrote to tun");
                }
                Err(error) => error!("Error with reading from sock")
            };
        }
    });

    while let Some(res) = set.join_next().await {}

    Ok(())
}