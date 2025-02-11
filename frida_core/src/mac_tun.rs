use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::{ffi::CString, process::Command};
use std::sync::Arc;
use std::error::Error;
use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::device::AbstractDevice;

extern "C" {
    fn open_utun(num: u64) -> i32;
}

fn cmd(cmd: &str, args: &[&str]) -> String {
    let ecode = Command::new(cmd)
        .args(args)
        .output();
    assert!(ecode.is_ok(), "Failed to execte {}", cmd);
    std::str::from_utf8(&ecode.as_ref().unwrap().stdout).unwrap().to_string()
}

fn get_utun() -> (i32, String) {
    for utun_n in 0..255 {
        let fd = unsafe { open_utun(utun_n) };
        if fd >= 0 {
            let name = format!("utun{}", utun_n);
            return (fd, name);
        }
    }
    panic!("{}", std::io::Error::last_os_error())
}

pub fn create(cfg: AbstractDevice) -> (DeviceReader, DeviceWriter) {
    let (fd, if_name) = get_utun();
    let reader = unsafe { File::from_raw_fd(fd) };
    let writer = unsafe { File::from_raw_fd(fd) };
    cmd("ifconfig", &[&if_name, &cfg.address.unwrap().to_string(), &cfg.destination.unwrap().to_string(), "netmask", &cfg.netmask.unwrap().to_string(), "up"]);
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
        Ok(self.writer.write(buf)?)
    }
}

impl DeviceReader {
    pub async fn read(&mut self, buf: &mut Vec<u8>) -> Result<usize, Box<dyn Error>> {
        Ok(self.reader.read(buf)?)
    }
}