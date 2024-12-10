//use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use std::os::fd::FromRawFd;

use std::fs::File;
use std::io::{Write, Read};

use libc::fdopen;
use std::ffi::CString;

pub fn create(cfg: i32) -> (DeviceReader, DeviceWriter) {
    let fd1 = cfg.clone();
    let fd2 = fd1.clone();
    let mut reader = unsafe { File::from_raw_fd(fd1) };
    let mut writer = unsafe { File::from_raw_fd(fd2) };

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