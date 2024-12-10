pub mod general {
    use frida_core::config::ClientConfiguration;
    use tokio_util::{codec::Framed, sync::CancellationToken};
    use tokio::{net::UdpSocket, sync::{Mutex, mpsc}, io::{AsyncWriteExt, AsyncReadExt}, fs::File};
    use log::{error, info, warn};
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm, Nonce};
    use base64::prelude::*;
    use std::{io::{Read, Write}, sync::Arc};
    use std::net::Ipv4Addr;
    
    use x25519_dalek::{PublicKey, StaticSecret};
    use frida_core::udp::{UDPVpnPacket, UDPVpnHandshake, UDPSerializable};
    use frida_core::{DeviceReader, DeviceWriter};

    pub trait VpnClient {
        async fn start(&self);
    }
    
    pub struct CoreVpnClient {
        pub client_config: ClientConfiguration,
        pub close_token: CancellationToken
    }

    impl CoreVpnClient {
         pub async fn start(&mut self, sock: UdpSocket, mut dev_reader: DeviceReader, mut dev_writer: DeviceWriter, mtu: u16) {
            info!("Starting client...");
    
            let dr_cancel: CancellationToken = CancellationToken::new();
            let sr_cancel: CancellationToken = CancellationToken::new();
        
            let sock_rec = Arc::new(sock);
            let sock_snd = sock_rec.clone();
        
            let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let (dx, mut mx) = mpsc::unbounded_channel::<Vec<u8>>();
        
            let cipher_shared: Arc<Mutex<Option<x25519_dalek::SharedSecret>>> = Arc::new(Mutex::new(None));
        
            let priv_key = BASE64_STANDARD.decode(&self.client_config.client.private_key).unwrap();
            
            let cipher_shared_clone = cipher_shared.clone();
        
            let pkey = BASE64_STANDARD.decode(&self.client_config.client.public_key).unwrap();
            let handshake = UDPVpnHandshake{ public_key: pkey, request_ip: self.client_config.client.address.parse::<Ipv4Addr>().unwrap() };
            let mut nz = 0;
            while nz < 25 {
                sock_snd.send(&handshake.serialize()).await.unwrap();
                nz += 1
            }
            //sock_snd.send(&handshake.serialize()).await.unwrap();
        
            let s_cipher = cipher_shared.clone();
    
            let _ = dev_writer.write(&handshake.serialize()).await;
    
            let mut buf1 = vec![0; 4096]; // should be changed to less bytes

            tokio::spawn(async move {
                let mut buf = vec![0; mtu.into()]; // mtu
                loop {
                    match dev_reader.read(&mut buf).await {
                        Ok(n) => {
                            info!("Read from tun."); // hex::encode(&buf[..n])
                            dx.send(buf[..n].to_vec()).unwrap();
                        },
                        Err(e) => { error!("Read failed {}", e); }
                    }
                }
            });

            loop {
                tokio::select! {
                    _ = self.close_token.cancelled() => {
                        info!("Cancellation token has been thrown");
                        sr_cancel.cancel();
                        dr_cancel.cancel();
                        return;
                    }
                    rr = rx.recv() => {
                        if let Some(bytes) = rr {
                            info!("Write to tun. len={:?}", bytes.len());
                            
                            if let Err(e) = dev_writer.write(&bytes).await {
                                error!("Writing error: {:?}", e);
                            }
                           /* if let Err(e) = self.dev_writer.flush().await {
                                error!("Flushing error: {:?}", e);
                            }*/
                        }
                    }
                    rr2 = mx.recv() => {
                        if let Some(bytes) = rr2 {
                            info!("Got info for sending");
                            let s_c = s_cipher.lock().await;
                            
                            if s_c.is_some() {
                                let aes = Aes256Gcm::new(s_c.as_ref().unwrap().as_bytes().into());
                                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                                let ciphered_data = aes.encrypt(&nonce, &bytes[..]);
                                
                                if let Ok(ciphered_d) = ciphered_data {
                                    let vpn_packet = UDPVpnPacket{ data: ciphered_d, nonce: nonce.to_vec()};
                                    let serialized_data = vpn_packet.serialize();
                                    info!("Write to socket");
                                    sock_snd.send(&serialized_data).await.unwrap();
                                } else {
                                    error!("Socket encryption failed.");
                                }
                            } else {
                                error!("There is no shared_secret in main loop");
                            }
                        }
                    }
                    rr = sock_rec.recv(&mut buf1) => {
                        if let Ok(l) = rr {
                            info!("Read from socket");
                            let mut s_cipher = cipher_shared_clone.lock().await;
                            match buf1.first() {
                                Some(h) => {
                                    match h {
                                        0 => {
                                            let handshake = UDPVpnHandshake::deserialize(&(buf1[..l].to_vec()));
                                            let mut k = [0u8; 32];
                                            for (&x, p) in handshake.public_key.iter().zip(k.iter_mut()) {
                                                *p = x;
                                            }
                                            let mut k1 = [0u8; 32];
                                            for (&x, p) in priv_key.iter().zip(k1.iter_mut()) {
                                                *p = x;
                                            }
                                            *s_cipher = Some(StaticSecret::from(k1)
                                                .diffie_hellman(&PublicKey::from(k)));
                                        }, // handshake
                                        1 => {
                                            let wrapped_packet = UDPVpnPacket::deserialize(&(buf1[..l].to_vec()));
                                            if s_cipher.is_some() {
                                                let aes = Aes256Gcm::new(s_cipher.as_ref().unwrap().as_bytes().into());
                                                let nonce = Nonce::clone_from_slice(&wrapped_packet.nonce);
                                                match aes.decrypt(&nonce, &wrapped_packet.data[..]) {
                                                    Ok(decrypted) => { let _ = tx.send(decrypted); },
                                                    Err(error) => { error!("Decryption error! {:?}", error); }
                                                }
                                            } else {
                                                warn!("There is no static_secret");
                                            }
                                        }, // payload
                                        2 => { info!("Got keepalive packet"); },
                                        _ => { error!("Unexpected header value."); }
                                    }
                                },
                                None => { error!("There is no header."); }
                            }
                            drop(s_cipher);
                        }
                    }
                };
            }
        }
    }
}

pub mod android {
    #![cfg(target_os = "android")]
    use crate::client::general::{VpnClient, CoreVpnClient};
    use frida_core::config::ClientConfiguration;
    use tokio_util::sync::CancellationToken;
    use std::os::fd::FromRawFd;
    use tokio::{net::UdpSocket, sync::{Mutex, mpsc}, io::{BufReader, BufWriter, AsyncWriteExt, AsyncReadExt}, fs::File};
    use log::{error, info, warn};

    pub struct AndroidClient {
        pub client_config: ClientConfiguration,
        pub fd: i32,
        pub close_token: CancellationToken
    }
    
    impl VpnClient for AndroidClient {
        async fn start(&self) {
            info!("FD: {:?}", &self.fd);
            let mtu: u16 = 1400;
            let mut client = CoreVpnClient{client_config: self.client_config.clone(), close_token: self.close_token.clone()};
            info!("SSS: {:?}", &self.client_config.server.endpoint);
            let (reader, writer) = frida_core::create(self.fd);
            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            sock.connect(&self.client_config.server.endpoint).await.unwrap();
            client.start(sock, reader, writer, mtu).await;
        }
    }
}

pub mod desktop {
    #![cfg(not(target_os = "android"))]
    use std::net::Ipv4Addr;

    use crate::client::general::{CoreVpnClient, VpnClient};
    use frida_core::config::ClientConfiguration;
    use frida_core::create;
    use frida_core::device::AbstractDevice;
    use log::info;
    use tokio::net::UdpSocket;

    #[cfg(target_os = "linux")]
    use regex::Regex;


    #[cfg(target_os = "linux")]
    fn configure_routes(endpoint_ip: &str) {
        let mut if_out = std::process::Command::new("ip")
            .arg("-4")
            .arg("route")
            .arg("show")
            .arg("default")
            .output()
            .expect("Failed to get default route");

        if !if_out.status.success() {
            log::error!("Failed to execute ip route command: {:?}", String::from_utf8_lossy(&if_out.stderr));
        }
        
        let r = std::str::from_utf8(&if_out.stdout).unwrap();

        let mut gateway = None;
        let mut if_name = None;

        let rg = Regex::new(r"default via .+ dev ").unwrap();
    
        if let Some(m) = rg.find(r) { // gateway
            gateway = Some(&m.as_str()[12..m.len()-5]);
        }
    
        let rg = Regex::new(r"dev .+ proto").unwrap();
        if let Some(m) = rg.find(r) { // name
            if_name = Some(&m.as_str()[4..m.len()-6]);
        }
        
        info!("Main interface: {:?}", &if_name.unwrap());

        let inter_name = if_name.unwrap();
    
        info!("Main network interface: {:?}", &gateway.unwrap());
        
        let mut ip_output = std::process::Command::new("sudo")
            .arg("route")
            .arg("add")
            .arg("-host")
            .arg(endpoint_ip)
            .arg("gw")
            .arg(&gateway.unwrap()) // default interface gateway
            .arg("dev")
            .arg(&inter_name) // default interface
            .output()
            .expect("Failed to execute route command.");
    
        if !ip_output.status.success() {
            log::error!("Failed to execute route command: {:?}", String::from_utf8_lossy(&ip_output.stderr));
        }

        let mut ip_output = std::process::Command::new("sudo")
            .arg("ip")
            .arg("route")
            .arg("add")
            .arg("0.0.0.0/0")
            .arg("dev")
            .arg("tun0") // tun adapter name
            .output()
            .expect("Failed to execute ip route command.");

        if !ip_output.status.success() {
            log::error!("Failed to execute ip route command: {:?}", String::from_utf8_lossy(&ip_output.stderr));
        }

        let mut ip_output = std::process::Command::new("sudo")
            .arg("ip")
            .arg("route")
            .arg("add")
            .arg("128.0.0.0/1")
            .arg("dev")
            .arg("tun0") // tun adapter name
            .output()
            .expect("Failed to execute ip route command.");

        if !ip_output.status.success() {
            log::error!("Failed to execute ip route command: {:?}", String::from_utf8_lossy(&ip_output.stderr));
        }

        let mut ip_output = std::process::Command::new("sudo")
            .arg("route")
            .arg("add")
            .arg("-host")
            .arg(endpoint_ip)
            .arg("gw")
            .arg(&gateway.unwrap()) // default interface gateway
            .arg("dev")
            .arg(&inter_name) // default interface
            .output()
            .expect("Failed to execute route command.");
    
        if !ip_output.status.success() {
            log::error!("Failed to execute route command: {:?}", String::from_utf8_lossy(&ip_output.stderr));
        }
    }

    pub struct DesktopClient {
        pub client_config: ClientConfiguration
    }
    
    impl VpnClient for DesktopClient {
        async fn start(&self) {
            info!("client_address: {:?}", &self.client_config.client.address);
            let mut config = AbstractDevice::default();
            let mtu: u16 = 1400;
            config.address(self.client_config.client.address.parse().unwrap())
                .netmask(Ipv4Addr::new(255, 255, 255, 255))
                .destination(Ipv4Addr::new(10, 66, 66, 1))
                .mtu(mtu)
                .tun_name("tun0");
        
            info!("SSS: {:?}", &self.client_config.server.endpoint);
            let sock = UdpSocket::bind(("0.0.0.0", 0)).await.unwrap();
            sock.connect(&self.client_config.server.endpoint).await.unwrap();

            let (dev_reader, dev_writer) = create(config);

            let mut client = CoreVpnClient{ client_config: self.client_config.clone(), close_token: tokio_util::sync::CancellationToken::new()};
           
            info!("Platform specific code");
            #[cfg(target_os = "linux")]
            {
                let s_a: std::net::SocketAddr = self.client_config.server.endpoint.parse().unwrap();
                configure_routes(&s_a.ip().to_string());
            }
            
            client.start(sock, dev_reader, dev_writer, mtu).await;
        }
    }
}