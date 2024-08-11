use tokio::{net::UdpSocket, sync::{mpsc, Mutex}};
use tokio::task::JoinSet;
use std::{borrow::{Borrow, BorrowMut}, future::IntoFuture, io::{self, Read, Write}, net::{SocketAddr, Ipv4Addr, IpAddr}, sync::{Arc}, thread, time};
use std::process::Command;
use clap::{App, Arg};
use env_logger::Builder;
use log::{error, info, LevelFilter};
use tun::platform::Device;
use serde_derive::Serialize;
use serde_derive::Deserialize;
//use packet::{builder::Builder, icmp, ip, Packet};
use std::collections::HashMap;

pub async fn server_mode() {
    info!("Starting server...");
    
    let mut config = tun::Configuration::default();
    config.address("10.8.0.1");
    config.name("tun0");
    config.up();

    #[cfg(target_os = "linux")]
	config.platform(|config| {
		config.packet_information(true);
	});

    let tun_receiver = Arc::new(Mutex::new(tun::create(&config).unwrap()));
    let tun_sender = tun_receiver.clone();

    let clients_inserter = Arc::new(Mutex::new(HashMap::new()));
    let clients_getter = clients_inserter.clone();

    let receiver_sock = Arc::new(match UdpSocket::bind("192.168.0.5:8879".parse::<SocketAddr>().unwrap()).await {
        Ok(s) => s,
        Err(_error) => panic!("Cannot bind to address")
    });
    let sender_sock = receiver_sock.clone();

    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);
    let (mx, mut dx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);

    let mut set = JoinSet::new();

    // tun 2 socket
    set.spawn(async move {
        while let Some((bytes, addr)) = rx.recv().await {
            let len = sender_sock.send_to(&bytes, &addr).await.unwrap();
            info!("{:?} bytes sent to socket", len);
        }
    });

    // socket 2 tun
    set.spawn(async move {
        while let Some((bytes, addr)) = dx.recv().await {
            let mut m = clients_inserter.lock().await;
            m.insert("10.0.8.2", addr);
            let mut ltun = tun_sender.lock().await;
            let len = match ltun.write(&bytes) {
                Ok(l) => l,
                Err(error) => {
                    error!("Failed to write to tun!");
                    0
                }
            };
            info!("{:?} bytes sent to tun", len);
        }
    });

    // socket 2 tun
    set.spawn(async move {
        let mut buf = [0; 1024];
        while let Ok((len, addr)) = receiver_sock.recv_from(&mut buf).await {
            info!("{:?} bytes received from {:?}", len, addr);
            mx.send((buf[..len].to_vec(), addr)).await.unwrap();
        }
    });


    // tun 2 socket
    set.spawn(async move {
        let mut buf = [0; 1024];
        let mut ltun: tokio::sync::MutexGuard<Device> = tun_receiver.lock().await;
        loop {
            let len = match ltun.read(&mut buf) {
                Ok(l) => l,
                Err(error) => {
                    error!("Problem with reading from tun: {error:?}");
                    0
                }
            };
            info!("{:?} bytes received from tun", len);
            let m = clients_getter.lock().await;
            match m.get(&"10.0.8.2") {
                Some(&addr) => tx.send((buf[..len].to_vec(), addr)).await.unwrap(),
                None => error!("There's no client!")
            }
        }
    });
    





   /* let sock_main = sock.clone();
    
    let clients_main = clients.clone();
    

    let tun_device_clone = tun_device.clone();
    let sock_clone = sock.clone();
    let clients_clone = clients.clone();
    let tun_device_clone_second = tun_device.clone();
    
    let mut set = JoinSet::new();

    set.spawn(async move {
        let mut buf = [0; 1024];
        loop {
            let mut tun = tun_device_clone_second.lock().await;
            let len = match tun.read(&mut buf) {
                Ok(l) => l,
                Err(error) => {
                    error!("Problem with reading from tun: {error:?}");
                    0
                },
            };
            
            if len <= 0 { continue; }
    
            info!("{:?} bytes received from tun", len);
            let sock_main_instance = sock_main.lock().await;
            let clients_main_instance = clients_main.lock().await;
            match clients_main_instance.get(&"10.8.0.2") {
                Some(&addr) => {
                    sock_main_instance.send_to(&buf, addr);
                    info!("bytes sent to socket");
                },
                None => error!("There is no client..."),
            }
        }
    });

    set.spawn(async move {
        let mut buf = [0; 1024];
        loop {
            let sock = sock_clone.lock().await;
            let (len, addr) = match sock.recv_from(&mut buf).await {
                Err(error) => {
                    error!("Problem with reading from socket: {error:?}");
                    (0, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
                },
                Ok(l) => l,
            };

            if len <= 0 { continue; }
            
            let mut tun = tun_device_clone.lock().await;
            let mut clients = clients_clone.lock().await;

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
    });*/

   /* let tasks = vec![
        tokio::spawn(),
        
        tokio::spawn()
    ];

    futures::future::join_all(tasks).await;*/

    while let Some(res) = set.join_next().await {}
}