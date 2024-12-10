use wintun::Session;

use std::sync::Arc;
use std::error::Error;

use crate::device::AbstractDevice;

pub fn create(cfg: AbstractDevice) -> (DeviceReader, DeviceWriter) {
    //Unsafe because we are loading an arbitrary dll file
    let wintun = unsafe { wintun::load_from_path("wintun.dll") }
    .expect("Failed to load wintun dll");

    let tun_name = match cfg.tun_name {
        Some(n) => n,
        None => "Demo".into()
    };

    //Try to open an adapter with the certain name
    let adapter = match wintun::Adapter::open(&wintun, &tun_name) {
    Ok(a) => a,
    Err(_) => {
            wintun::Adapter::create(&wintun, &tun_name, "FridaVPN", None)
                .expect("Failed to create wintun adapter!")
        }
    };

    let args = &["interface", "ipv4", "set", "interface", &tun_name, "metric=5"];
    let _ = wintun::run_command("netsh", args).unwrap();

    let mut gateway = "gateway=".to_owned();
    gateway.push_str(&cfg.destination.unwrap().to_string());

    let mut address = cfg.address.unwrap().to_string().to_owned();
    address.push_str("/32");

    let args = &[
        "interface",
        "ipv4",
        "set",
        "address",
        &tun_name,
        "static",
        &address,
        &gateway,
    ];
    
    let _ = wintun::run_command("netsh", args).unwrap();

    let mut mtu = "mtu=".to_owned();
    mtu.push_str(&cfg.mtu.unwrap().to_string());

    let args = &[
        "interface",
        "ipv4",
        "set",
        "subinterface",
        &tun_name,
        &mtu,
        "store=persistent"
    ];

    let _ = wintun::run_command("netsh", args).unwrap();

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
    let reader_session = session.clone();
    let writer_session = session.clone();

    (DeviceReader{ session: reader_session }, DeviceWriter{ session: writer_session })
}

pub struct DeviceWriter {
    session: Arc<Session>
}

pub struct DeviceReader {
    session: Arc<Session>
}

impl DeviceWriter {
    pub async fn write(&mut self, buf: &Vec<u8>) -> Result<usize, Box<dyn Error>> {
        let mut write_pack = self.session.allocate_send_packet(buf.len() as u16)?;
        write_pack.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(write_pack);
        Ok(buf.len())
    }
}

impl DeviceReader {
    pub async fn read(&mut self, buf: &mut Vec<u8>) -> Result<usize, Box<dyn Error>> {
        let packet = self.session.receive_blocking()?;
        *buf = packet.bytes().to_vec();
        Ok(buf.len())
    }
}