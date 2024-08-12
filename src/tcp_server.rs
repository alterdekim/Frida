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
                    sock_writer.write(&bytes).await.unwrap();
                }
            }
        });

        tokio::spawn(async move {
            let mut buf = vec![0; 2048];
            loop {
                let n = sock_reader.try_read(&mut buf).unwrap();
                thread_tx.send(buf[..n].to_vec()).unwrap();
            }
        });
    }

   /* let mut set = JoinSet::new();

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

    Ok(())*/
}