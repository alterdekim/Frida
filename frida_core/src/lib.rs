pub mod device;
pub mod tun;
pub mod obfs;
pub mod udp;
pub mod config;

#[cfg(target_os = "windows")]
mod win_tun;

#[cfg(target_os = "windows")]
pub use r#win_tun::*;

#[cfg(target_os = "linux")]
mod linux_tun;

#[cfg(target_os = "linux")]
pub use r#linux_tun::*;