use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use std::os::fd::FromRawFd;

pub fn create(cfg: i32) -> (DeviceReader, DeviceWriter) {
    // check this if android build won't work
    let fd1 = cfg.clone();
    let fd2 = fd1.clone();
    let mut reader = unsafe { File::from_raw_fd(fd1) };
    //let mut writer = unsafe { File::from_raw_fd(fd2) };
    
    (DeviceReader {reader}, DeviceWriter {None})
}

pub struct DeviceWriter {
    writer: Option<File>
}

pub struct DeviceReader {
    reader: File
}

impl DeviceWriter {
    pub async fn write(&mut self, buf: &Vec<u8>) -> Result<usize, Box<dyn Error>> {
        if self.writer.is_some() {
            return Ok(self.writer.write(buf).await?);
        }
        Ok(0)
    }
}

impl DeviceReader {
    pub async fn read(&mut self, buf: &mut Vec<u8>) -> Result<usize, Box<dyn Error>> {
        Ok(self.reader.read_buf(buf).await?)
    }
}