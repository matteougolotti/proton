use super::connection::Connection;

const BOOTSTRAP_DNS_SEEDS: [&str; 5] = [
    "seed.bitcoinstats.com:8333",
    "seed.bitcoin.sipa.be:8333",
    "dnsseed.bluematt.me:8333",
    "dnsseed.bitcoin.dashjr.org:8333",
    "bitseed.xf2.org:8333",
];

pub struct Node {
    stop: std::sync::RwLock<bool>,
}

impl Node {
    pub fn new() -> Self {
        Self{
            stop: std::sync::RwLock::new(false),
        }
    }

    pub fn start(&self) -> std::io::Result<()> {
        let connection: Connection = Connection::new(
            String::from(BOOTSTRAP_DNS_SEEDS[0]),
            super::messages::Network::MAINNET,
            super::messages::PROTOCOL_VERSION,
        );

        connection.connect().unwrap();

        Ok(())
    }

    pub fn stop(&self) {
        let mut stop = self.stop.write().unwrap();
        *stop = true;
    }
}
