use bitcoin::connection::Connection;

const BOOTSTRAP_DNS_SEEDS: [&str; 5] = [
    "seed.bitcoinstats.com:8333",
    "seed.bitcoin.sipa.be:8333",
    "dnsseed.bluematt.me:8333",
    "dnsseed.bitcoin.dashjr.org:8333",
    "bitseed.xf2.org:8333",
];

fn main() -> std::io::Result<()> {
    let connection: Connection = Connection{
        peer: String::from(BOOTSTRAP_DNS_SEEDS[0]),
        network: bitcoin::messages::Network::MAINNET,
        version: std::cell::Cell::new(bitcoin::messages::PROTOCOL_VERSION),
        stop: std::sync::RwLock::new(false),
    };

    connection.connect().unwrap();

    Ok(())
}
