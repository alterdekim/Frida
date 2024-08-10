use tokio::{net::UdpSocket, sync::{mpsc, Mutex}};
use std::{borrow::{Borrow, BorrowMut}, future::IntoFuture, io::{self, Read, Write}, net::{SocketAddr, Ipv4Addr, IpAddr}, sync::Arc, thread, time};
use std::process::Command;
use clap::{App, Arg};
use env_logger::Builder;
use log::{error, info, LevelFilter};
use tun::platform::Device;
use serde_derive::Serialize;
use serde_derive::Deserialize;
//use packet::{builder::Builder, icmp, ip, Packet};
use std::collections::HashMap;

pub async fn server_mode() -> io::Result<()> {
    info!("Starting server...");
    
    let mut config = tun::Configuration::default();
    config.address("10.8.0.1");
    config.name("tun0");

    let tun_device = Arc::new(Mutex::new(tun::create(&config).unwrap()));

    let sock = Arc::new(Mutex::new(UdpSocket::bind("127.0.0.1:8879".parse::<SocketAddr>().unwrap()).await?));

    let clients = Arc::new(Mutex::new(HashMap::new()));

    /* let r = Arc::new(sock);
    let s = r.clone();
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);

    tokio::spawn(async move {
        while let Some((bytes, addr)) = rx.recv().await {
            let len = s.send_to(&bytes, &addr).await.unwrap();
            info!("{:?} bytes sent", len);
        }
    });

    let mut buf = [0; 1024];
    loop {
        let (len, addr) = r.recv_from(&mut buf).await?;
        info!("{:?} bytes received from {:?}", len, addr);
        //tx.send((buf[..len].to_vec(), addr)).await.unwrap();
    }*/

    let sock_main = sock.clone();
    let remote_addr = "127.0.0.1:8879";
    let sock_main_instance = sock_main.lock().await;
    sock_main_instance.connect(remote_addr).await?;
    let clients_main = clients.clone();
    let clients_main_instance = clients_main.lock().await;

    let tun_device_clone = tun_device.clone();
    let sock_clone = sock.clone();
    let clients_clone = clients.clone();
    tokio::spawn(async move {
        let mut buf = [0; 1024];
        let mut tun = tun_device_clone.lock().await;
        let sock = sock_clone.lock().await;
        let mut clients = clients_clone.lock().await;
        loop {
            let (len, addr) = match sock.recv_from(&mut buf).await {
                Err(error) => {
                    error!("Problem with reading from socket: {error:?}");
                    (0, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
                },
                Ok(l) => l,
            };

            if len <= 0 { continue; }
            
            clients.insert("10.8.0.2", addr);
            info!("{:?} bytes received from {:?}", len, addr);
            
            let len = match tun.write(&buf) {
                Ok(l) => l,
                Err(error) => {
                    error!("Problem with writing to tun: {error:?}");
                    0
                }
            };

            info!("{:?} bytes sent to tun", len);
        }
    });

    let tun_device_clone_second = tun_device.clone();
    let mut buf = [0; 1024];
    let mut tun = tun_device_clone_second.lock().await;
    loop {
        let len = match tun.read(&mut buf) {
            Ok(l) => l,
            Err(error) => {
                error!("Problem with reading from tun: {error:?}");
                0
            },
        };
        
        if len <= 0 { continue; }

        info!("{:?} bytes received from tun", len);
       
        match clients_main_instance.get(&"10.8.0.2") {
            Some(&addr) => {
                let len = sock_main_instance.send_to(&buf, addr).await?;
                info!("{:?} bytes sent to socket", len);
            },
            None => error!("There is no client..."),
        }
    }
}