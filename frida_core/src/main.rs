use env_logger::Builder;
use log::{info, error, LevelFilter};

mod device;
mod tun;

#[cfg(target_os = "windows")]
mod win_tun;

#[cfg(target_os = "linux")]
mod linux_tun;

#[tokio::main]
async fn main() {
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();

    let (reader, writer) = tun::create_tun();

    let a = tokio::spawn(async move {
        let mut buf = Vec::new();
        info!("Started!");
        loop {
            // info!("We've got {} bytes of data!", c)
            let r = reader.read(&mut buf).await;
            match r {
                Ok(c) => {},
                Err(e) => error!("We've got a nasty error message!")
            }
        }
    });

    a.await;
}