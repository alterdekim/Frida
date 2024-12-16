use std::os::fd::{AsRawFd, FromRawFd};
use std::{ffi::CString, process::Command};
use std::sync::Arc;
use std::error::Error;
use log::info;
use nix::errno::Errno;
use nix::libc::{connect, sockaddr_ctl, CTLIOCGINFO};
use nix::sys::socket::{SockaddrLike, SockaddrStorage, UnixAddr};
use nix::{libc::{ctl_info, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL}, sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType, sockaddr}};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    let fd = socket(
        AddressFamily::System, 
            SockType::Datagram, 
            SockFlag::empty(), 
            Some(SockProtocol::KextControl)
        );

    if let Err(e) = fd {
        panic!("Unable to open socket! Error: {:?}", e);
    }

    let fd = fd.unwrap();

    let mut info: ctl_info = unsafe { std::mem::zeroed() };
    let ctl_name = CString::new("com.apple.net.utun_control").unwrap();
    ctl_name.as_bytes_with_nul()
        .iter()
        .enumerate()
        .for_each(|(i, &c)| info.ctl_name[i] = c as i8);

    if unsafe { nix::libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info) } < 0 {
        let err = Errno::last();
        panic!("ioctl CTLIOCGINFO failed: {}", err);
    }

    let mut sc = sockaddr_ctl {
        sc_len: std::mem::size_of::<sockaddr_ctl>() as u8,
        sc_family: nix::libc::AF_SYSTEM as u8,
        ss_sysaddr: nix::libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit: 0,
        sc_reserved: [0; 5]
    };

    let asc = &sc as *const sockaddr_ctl as *const sockaddr;
    let f = unsafe { connect(fd.as_raw_fd(), asc, size_of::<sockaddr_ctl>() as u32 ) };

    info!("utun interface created successfully, fd: {:?}", f);

    let mut reader = unsafe { File::from_raw_fd(f) };
    let mut writer = unsafe { File::from_raw_fd(f) };

    let mut address = cfg.address.unwrap().to_string();
    address.push_str("/24");

    /* 
    cmd("ip", &["addr", "add", "dev", iface.name(), &address]);
    cmd("ip", &["link", "set", "up", "dev", iface.name()]);

    let iface = Arc::new(iface);
    let writer = Arc::clone(&iface);
    let reader = Arc::clone(&iface);*/

    (DeviceReader {reader}, DeviceWriter {writer})
}

pub struct DeviceWriter {
    writer: File
}

pub struct DeviceReader {
    reader: File
}

impl DeviceWriter {
    pub async fn write(&mut self, buf: &Vec<u8>) -> Result<usize, Box<dyn Error>> {
        Ok(self.writer.write(buf).await?)
    }
}

impl DeviceReader {
    pub async fn read(&mut self, buf: &mut Vec<u8>) -> Result<usize, Box<dyn Error>> {
        Ok(self.reader.read_buf(buf).await?)
    }
}