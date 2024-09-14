include!(concat!(env!("OUT_DIR"), "/common.rs"));

impl From<uuid::Uuid> for Uuid {
    fn from(uuid: uuid::Uuid) -> Self {
        let (high, low) = uuid.as_u64_pair();
        Uuid { low, high }
    }
}

impl From<Uuid> for uuid::Uuid {
    fn from(uuid: Uuid) -> Self {
        uuid::Uuid::from_u64_pair(uuid.high, uuid.low)
    }
}

impl ToString for Uuid {
    fn to_string(&self) -> String {
        uuid::Uuid::from(self.clone()).to_string()
    }
}

impl From<std::net::Ipv4Addr> for Ipv4Addr {
    fn from(value: std::net::Ipv4Addr) -> Self {
        Self {
            addr: value.to_bits(),
        }
    }
}

impl From<Ipv4Addr> for std::net::Ipv4Addr {
    fn from(value: Ipv4Addr) -> Self {
        std::net::Ipv4Addr::from(value.addr)
    }
}

impl ToString for Ipv4Addr {
    fn to_string(&self) -> String {
        std::net::Ipv4Addr::from(self.addr).to_string()
    }
}
