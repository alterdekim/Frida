use wintun::Session;

use std::sync::Arc;
use std::error::Error;

pub fn create() -> (DeviceReader, DeviceWriter) {
    //Unsafe because we are loading an arbitrary dll file
    let wintun = unsafe { wintun::load_from_path("wintun.dll") }
    .expect("Failed to load wintun dll");

    //Try to open an adapter with the name "Demo"
    let adapter = match wintun::Adapter::open(&wintun, "Demo") {
    Ok(a) => a,
    Err(_) => {
            wintun::Adapter::create(&wintun, "Demo", "Example", None)
                .expect("Failed to create wintun adapter!")
        }
    };

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
    pub async fn write(&self, buf: &Vec<u8>) -> Result<usize, Box<dyn Error>> {
        let mut write_pack = self.session.allocate_send_packet(buf.len() as u16)?;
        write_pack.bytes_mut().copy_from_slice(buf);
        self.session.send_packet(write_pack);
        Ok(buf.len())
    }
}

impl DeviceReader {
    pub async fn read(&self, buf: &mut Vec<u8>) -> Result<usize, Box<dyn Error>> {
        let packet = self.session.receive_blocking()?;
        *buf = packet.bytes().to_vec();
        Ok(buf.len())
    }
}