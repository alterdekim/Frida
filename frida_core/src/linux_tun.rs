use std::sync::Arc;
use std::error::Error;
use tokio_tun::Tun;
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;

pub fn create() -> (DeviceReader, DeviceWriter) {
    let tun = Arc::new(
        Tun::builder()
            .name("")            // if name is empty, then it is set by kernel.
            .tap()               // uses TAP instead of TUN (default).
            .packet_info()       // avoids setting IFF_NO_PI.
            .up()                // or set it up manually using `sudo ip link set <tun-name> up`.
            .try_build()         // or `.try_build_mq(queues)` for multi-queue support.
            .unwrap(),
    );

    println!("tun created, name: {}, fd: {}", tun.name(), tun.as_raw_fd());

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
    pub async fn write(&self, buf: &Vec<u8>) -> Result<usize, Box<dyn Error>> {
        self.writer.send_all(buf).await
    }
}

impl DeviceReader {
    pub async fn read(&self, buf: &mut Vec<u8>) -> Result<usize, Box<dyn Error>> {
        self.reader.recv(buf).await
    }
}