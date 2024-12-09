
use std::net::Ipv4Addr;

#[derive(Default)]
pub struct AbstractDevice {
    pub(crate) address: Option<Ipv4Addr>,
    pub(crate) netmask: Option<Ipv4Addr>,
    pub(crate) destination: Option<Ipv4Addr>,
    pub(crate) mtu: Option<u16>,
    pub(crate) tun_name: Option<String>
}

impl AbstractDevice {
    pub fn address(&mut self, address: Ipv4Addr) -> &mut Self {
        self.address = Some(address);
        self
    }

    pub fn netmask(&mut self, netmask: Ipv4Addr) -> &mut Self {
        self.netmask = Some(netmask);
        self
    }

    pub fn destination(&mut self, destination: Ipv4Addr) -> &mut Self {
        self.destination = Some(destination);
        self
    }

    pub fn mtu(&mut self, mtu: u16) -> &mut Self {
        self.mtu = Some(mtu);
        self
    }

    pub fn tun_name<S: AsRef<str>>(&mut self, tun_name: S) -> &mut Self {
        self.tun_name = Some(tun_name.as_ref().into());
        self
    }
}