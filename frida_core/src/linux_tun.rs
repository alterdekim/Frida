use std::sync::Arc;
use std::error::Error;
use tokio_tun::Tun;
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use crate::device::AbstractDevice;
use log::info;

pub fn create(cfg: AbstractDevice) -> (DeviceReader, DeviceWriter) {

    let builder = Tun::builder();

    if cfg.tun_name.is_some() {
        builder.name(&cfg.tun_name.unwrap());
    }

    if cfg.mtu.is_some() {
        builder.mtu(cfg.mtu.unwrap().into());
    }

    if cfg.address.is_some() {
        builder.address(cfg.address.unwrap());
    }

    if cfg.netmask.is_some() {
        builder.netmask(cfg.netmask.unwrap());
    }

    if cfg.destination.is_some() {
        builder.destination(cfg.destination.unwrap());
    }

    let tun = Arc::new(
        builder
            .up()                // or set it up manually using `sudo ip link set <tun-name> up`.
            .try_build()         // or `.try_build_mq(queues)` for multi-queue support.
            .unwrap(),
    );

    info!("tun created, name: {}, fd: {}", tun.name(), tun.as_raw_fd());

    let tun_writer = tun.clone();

    (DeviceReader {reader: tun}, DeviceWriter {writer: tun_writer})
}

pub struct DeviceWriter {
    writer: Arc<Tun>
}

pub struct DeviceReader {
    reader: Arc<Tun>
}

impl DeviceWriter {
    pub async fn write(&mut self, buf: &Vec<u8>) -> Result<usize, Box<dyn Error>> {
        self.writer.send_all(buf).await?;
        Ok(0)
    }
}

impl DeviceReader {
    pub async fn read(&mut self, buf: &mut Vec<u8>) -> Result<usize, Box<dyn Error>> {
        let n = self.reader.recv(buf).await?;
        Ok(n)
    }
}