
#[derive(Default)]
pub struct AbstractDevice {
    address: String,
    netmask: String,
    destination: String,
    mtu: u16,
    tun_name: String
}

impl AbstractDevice {
    fn address(&mut self, address: String) {
        self.address = address;
    }

    fn netmask(&mut self, netmask: String) {
        self.netmask = netmask;
    }

    fn destination(&mut self, destination: String) {
        self.destination = destination;
    }

    fn mtu(&mut self, mtu: u16) {
        self.mtu = mtu;
    }

    fn tun_name(&mut self, tun_name: String) {
        self.tun_name = tun_name;
    }
}