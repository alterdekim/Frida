use serde_derive::Serialize;
use serde_derive::Deserialize;

#[derive(Serialize, Deserialize)]
struct VpnPacket {
    data: Vec<u8>,
}