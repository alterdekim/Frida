use tokio::{net::UdpSocket, sync::{mpsc, Mutex}};
use tokio::task::JoinSet;
use packet::{builder::Builder, icmp, ip, Packet};
use std::io::{Read, Write};
use std::sync::mpsc::Receiver;
use tun2::BoxError;
use log::{error, info, LevelFilter};
use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::HashMap;


pub async fn server_mode() -> Result<(), BoxError> {
    info!("Starting server...");
    
    let mut config = tun2::Configuration::default();
    config.address("10.8.0.1");
    config.tun_name("tun0");
    config.up();

    #[cfg(target_os = "linux")]
	config.platform_config(|config| {
		config.packet_information(true);
	});

    let dev = tun2::create(&config)?;
    let (mut reader, mut writer) = dev.split();

    let clients_inserter = Arc::new(Mutex::new(HashMap::<&str, UdpSocket>::new()));
    let clients_getter = clients_inserter.clone();

    let receiver_sock = Arc::new(match UdpSocket::bind("192.168.0.5:8879".parse::<SocketAddr>().unwrap()).await {
        Ok(s) => s,
        Err(_error) => panic!("Cannot bind to address")
    });

    let mut set = JoinSet::new();

    set.spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let size = reader.read(&mut buf)?;
            let pkt = &buf[..size];
            use std::io::{Error, ErrorKind::Other};
            let m = clients_getter.lock().await;
            match m.get(&"10.0.8.2") {
                Some(&ref sock) => { sock.send(&pkt).await.unwrap(); info!("Wrote to sock") },
                None => { error!("There's no client!") }
            };
            drop(m);
            ()
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });

    set.spawn(async move {
        let mut buf = [0; 4096];
        loop {
            if let Ok((len, addr)) = receiver_sock.recv_from(&mut buf).await {
                let mut m = clients_inserter.lock().await;
                if !m.contains_key(&"10.0.8.2") {
                    let cl = UdpSocket::bind("0.0.0.0:59611").await?;
                    cl.connect(addr).await?;
                    m.insert("10.0.8.2", cl);
                }
                drop(m);
                writer.write_all(&buf[..len])?;
                info!("Wrote to tun");
            }
        }
    });

    while let Some(res) = set.join_next().await {}

    Ok(())
}