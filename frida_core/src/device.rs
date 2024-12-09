
use std::net::IpAddr;

#[derive(Default)]
pub struct AbstractDevice {
    pub(crate) address: Option<IpAddr>,
    pub(crate) netmask: Option<IpAddr>,
    pub(crate) destination: Option<IpAddr>,
    pub(crate) mtu: Option<u16>,
    pub(crate) tun_name: Option<String>
}

impl AbstractDevice {
    pub fn address(&mut self, address: IpAddr) -> &mut Self {
        self.address = Some(address);
        self
    }

    pub fn netmask(&mut self, netmask: IpAddr) -> &mut Self {
        self.netmask = Some(netmask);
        self
    }

    pub fn destination(&mut self, destination: IpAddr) -> &mut Self {
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