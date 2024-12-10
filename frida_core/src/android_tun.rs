use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use std::os::fd::FromRawFd;

pub fn create(cfg: i32) -> (DeviceReader, DeviceWriter) {
    // check this if android build won't work
    let mut reader = unsafe { File::from_raw_fd(cfg) };
    let mut writer = unsafe { File::from_raw_fd(cfg) };
    
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