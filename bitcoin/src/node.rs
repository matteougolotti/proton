use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use super::connection::Connection;
use super::messages::{
    Address,
    Message,
};

const BOOTSTRAP_DNS_SEEDS: [&str; 5] = [
    "seed.bitcoinstats.com:8333",
    "seed.bitcoin.sipa.be:8333",
    "dnsseed.bluematt.me:8333",
    "dnsseed.bitcoin.dashjr.org:8333",
    "bitseed.xf2.org:8333",
];

pub struct Node {
    peers: std::collections::HashSet<Address>,
    stop: std::sync::RwLock<bool>,
}

impl Node {
    pub fn new() -> Self {
        Self{
            peers: std::collections::HashSet::new(),
            stop: std::sync::RwLock::new(false),
        }
    }

    pub fn start(&self) -> std::io::Result<()> {
        let (tx, rx): (Sender<Message>, Receiver<Message>) = channel();

        let connection: Connection = Connection::new(
            String::from(BOOTSTRAP_DNS_SEEDS[0]),
            super::messages::Network::MAINNET,
            super::messages::PROTOCOL_VERSION,
            tx,
        );

        thread::spawn(move || {
            connection.connect().unwrap();
        });

        while !(*self.stop.read().unwrap()) {
            match rx.recv() {
                Ok(message) => self.handle_message(&message),
                _ => (),
            }
        }

        Ok(())
    }

    pub fn stop(&self) {
        let mut stop = self.stop.write().unwrap();
        *stop = true;
    }

    fn handle_message(&self, message: &Message) {
        match message {
            _ => (),
        }
    }
}
