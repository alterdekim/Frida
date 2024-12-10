use std::process::Command;
use std::sync::Arc;
use tun_tap::{Iface, Mode};

use crate::device::AbstractDevice;

fn cmd(cmd: &str, args: &[&str]) {
    let ecode = Command::new("ip")
        .args(args)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(ecode.success(), "Failed to execte {}", cmd);
}

pub fn create(cfg: AbstractDevice) -> (DeviceReader, DeviceWriter) {
    let iface = Iface::new("tun%d", Mode::Tun).unwrap();

    let address = cfg.address.unwrap().to_string();
    address.push_str("/24");

    cmd("ip", &["addr", "add", "dev", iface.name(), address]);
    cmd("ip", &["link", "set", "up", "dev", iface.name()]);

    let iface = Arc::new(iface);
    let writer = Arc::clone(&iface);
    let reader = Arc::clone(&iface);

    (DeviceReader {reader}, DeviceWriter {writer})
}

pub struct DeviceWriter {
    writer: Arc<Iface>
}

pub struct DeviceReader {
    reader: Arc<Iface>
}

impl DeviceWriter {
    pub async fn write(&self, buf: &Vec<u8>) -> Result<usize, Box<dyn Error>> {
        self.send(buf)
    }
}

impl DeviceReader {
    pub async fn read(&self, buf: &mut Vec<u8>) -> Result<usize, Box<dyn Error>> {
        self.recv(buf)
    }
}