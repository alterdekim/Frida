use std::sync::Arc;
use std::error::Error;

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

    let (mut reader, mut _writer) = tokio::io::split(tun);
}

pub struct DeviceWriter {

}

pub struct DeviceReader {

}

impl DeviceWriter {
    pub async fn write(&self, buf: &Vec<u8>) -> Result<usize, Box<dyn Error>> {
    }
}

impl DeviceReader {
    pub async fn read(&self, buf: &mut Vec<u8>) -> Result<usize, Box<dyn Error>> {
    }
}