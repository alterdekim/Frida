#[cfg(target_os = "windows")]
use crate::win_tun::{DeviceReader, DeviceWriter, create};

#[cfg(target_os = "linux")]
use crate::linux_tun::{DeviceReader, DeviceWriter, create};

pub(crate) fn create_tun() -> (DeviceReader, DeviceWriter) {
    #[cfg(target_os = "windows")]
    create()
}