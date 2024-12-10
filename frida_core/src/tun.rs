use crate::device::AbstractDevice;

#[cfg(target_os = "windows")]
use crate::win_tun::{DeviceReader, DeviceWriter, create};

#[cfg(target_os = "linux")]
use crate::linux_tun::{DeviceReader, DeviceWriter, create};

#[cfg(target_os = "macos")]
use crate::mac_tun::{DeviceReader, DeviceWriter, create};

pub fn create_tun(cfg: AbstractDevice) -> (DeviceReader, DeviceWriter) {
    create(cfg)
}