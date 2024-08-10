use tokio::{net::UdpSocket, sync::{mpsc, Mutex}};
use std::{borrow::{Borrow, BorrowMut}, future::IntoFuture, io::{self, Read, Write}, net::SocketAddr, sync::Arc, thread, time};
use std::process::Command;
use clap::{App, Arg};
use env_logger::Builder;
use log::{error, info, LevelFilter};
use tun::platform::Device;
use serde_derive::Serialize;
use serde_derive::Deserialize;

pub async fn client_mode(remote_addr: &str) -> io::Result<()> {
    info!("Starting client...");

    let mut config = tun::Configuration::default();
    config.address("10.8.0.2");
    config.netmask("128.0.0.0");
    config.destination("0.0.0.0");
    config.name("tun0");

    let tun_device = Arc::new(Mutex::new(tun::create(&config).unwrap()));

    let sock = Arc::new(Mutex::new(UdpSocket::bind("0.0.0.0:59611").await?));
    
    let sock_main = sock.clone();
    let sock_main_instance = sock_main.lock().await;
    sock_main_instance.connect(remote_addr).await?;

    let tun_device_clone = tun_device.clone();
    let sock_clone = sock.clone();
    tokio::spawn(async move {
        let mut buf = [0; 1024];
        let mut tun = tun_device_clone.lock().await;
        let sock = sock_clone.lock().await;
        loop {
            let len = match sock.recv(&mut buf).await {
                Err(error) => {
                    error!("Problem with reading from socket: {error:?}");
                    0
                },
                Ok(l) => l,
            };

            if len <= 0 { continue; }

            info!("{:?} bytes received from socket", len);
            
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
       
        let len = sock_main_instance.send(&buf).await?;
        info!("{:?} bytes sent to socket", len);
    }
}