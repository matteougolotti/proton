use std::net::IpAddr;
use std::time::SystemTime;

use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::{Receiver, Sender};

use super::connection::{
    Connection,
    ConnectionId,
    Message,
};
use super::messages::{
    Addr,
    Address,
    BitcoinMessage,
};

const BOOTSTRAP_DNS_SEEDS: [&str; 5] = [
    "seed.bitcoinstats.com:8333",
    "seed.bitcoin.sipa.be:8333",
    "dnsseed.bluematt.me:8333",
    "dnsseed.bitcoin.dashjr.org:8333",
    "bitseed.xf2.org:8333",
];

pub struct Node {
    connections: std::cell::RefCell<std::collections::HashMap<ConnectionId, Connection>>,
    peers: std::cell::RefCell<std::collections::HashMap<(IpAddr, u16), Address>>,
    stop: std::sync::RwLock<bool>,
}

impl Node {
    pub fn new() -> Self {
        Self{
            connections: std::cell::RefCell::new(std::collections::HashMap::new()),
            peers: std::cell::RefCell::new(std::collections::HashMap::new()),
            stop: std::sync::RwLock::new(false),
        }
    }

    pub async fn start(&self) -> std::io::Result<()> {
        let (tx, mut rx): (Sender<Message>, Receiver<Message>) = channel(256);

        let (conn_tx, conn_rx): (Sender<Message>, Receiver<Message>) = channel(256);
        let connection: Connection = Connection::new(
            0,
            String::from(BOOTSTRAP_DNS_SEEDS[0]),
            super::messages::Network::MAINNET,
            super::messages::PROTOCOL_VERSION,
        );

        tokio::spawn(async move {
            connection.run(conn_rx, tx).await.unwrap();
        });

        while !(*self.stop.read().unwrap()) {
            match rx.recv().await {
                Some(message) => self.handle_message(message),
                _ => (),
            }
        }

        Ok(())
    }

    pub fn stop(&self) {
        let mut stop = self.stop.write().unwrap();
        *stop = true;
    }

    fn handle_message(&self, message: Message) {
        match message {
            Message::IncomingBitcoinMessage((connection_id, message)) => {
                self.handle_bitcoin_message(connection_id, message);
            },
            Message::Disconnected(_connection_id) => {
                // We got disconnected on connection `connection_id`
                // TODO cleanup the connection state
                // TODO spawn a new connection to a new peer
            },
            _ => (),
        }
    }

    fn handle_bitcoin_message(&self, _connection_id: ConnectionId, message: BitcoinMessage) {
        match message {
            BitcoinMessage::Getaddr(_getaddr) => {
                println!("RECEIVED => getaddr");
            },
            BitcoinMessage::Addr(addr) => {
                println!("RECEIVED => addr");
                self.remove_old_peers();
                self.add_new_peers(addr);
            },
            BitcoinMessage::Getheaders(_getheaders) => {
                println!("RECEIVED => getheaders");
            },
            BitcoinMessage::Inv(inv) => {
                println!("RECEIVED => inv");
                inv.inv_vec.iter().for_each(|item| println!("{:?}", item));
            },
            _ => {
                println!("RECEIVED => unknown");
            },
        }
    }

    fn add_new_peers(&self, addr: Addr) {
        for address in addr.addr_list {
            let key = (address.ip, address.port);
            self.peers.borrow_mut().insert(key, address);
        }
    }

    fn remove_old_peers(&self) {
        let now: u32 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32;
        for (key, address) in self.peers.borrow_mut().iter() {
            if now - address.timestamp > 10800 {
                self.peers.borrow_mut().remove(key);
            }
        }
    }
}
