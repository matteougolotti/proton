use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use super::messages::{
    Message,
    Options,
    Packet,
    Serializable,
    Verack,
    Version,
};

use tokio::net::TcpStream;
use tokio::prelude::*;
use tokio::stream::StreamExt;

const MTU: usize = 1500;
const BOOTSTRAP_DNS_SEEDS: [&str; 5] = [
    "seed.bitcoinstats.com:8333",
    "seed.bitcoin.sipa.be:8333",
    "dnsseed.bluematt.me:8333",
    "dnsseed.bitcoin.dashjr.org:8333",
    "bitseed.xf2.org:8333",
];

pub struct Client {
    pub network: super::messages::Network,
    pub peers: HashSet<IpAddr>,
    pub connections: HashMap<SocketAddr, tokio::net::TcpStream>,
}

impl Client {
    pub fn new(network: super::messages::Network) -> Self {
        Self {
            network: network,
            peers: HashSet::new(),
            connections: HashMap::new(),
        }
    }

    pub async fn start(&self) {
        let mut rng = rand::thread_rng();
        let bootstrap_dns_seed = BOOTSTRAP_DNS_SEEDS[rng.gen_range(0, BOOTSTRAP_DNS_SEEDS.len())];
        println!("Connecting => {:x?}", bootstrap_dns_seed);

        let mut bootstrap_stream: tokio::net::TcpStream = TcpStream::connect(bootstrap_dns_seed).await.unwrap();
        self.connect(&mut bootstrap_stream).await;

        loop {
            // TODO
        }
    }

    pub async fn connect(&self, stream: &mut tokio::net::TcpStream) {
        // Send Version message
        self.send(stream,
            &Version::new(
                super::messages::Address::new(stream.local_addr().unwrap().ip()),
                super::messages::Address::new(stream.peer_addr().unwrap().ip()),
                1,
            ),
            &Options{version: super::messages::PROTOCOL_VERSION, is_version_message: true},
        ).await.unwrap();
        println!("SENT => Version");

        // Receive Version message
        let version: Box<Message> = self.receive(stream,
            &Options{version: super::messages::PROTOCOL_VERSION, is_version_message: true},
        ).await;
        println!("COMMAND (version) => {:x?}", std::str::from_utf8(&version.command));

        // Receive Verack message
        let verack: Box<Message> = self.receive(stream,
            &Options{version: super::messages::PROTOCOL_VERSION, is_version_message: false},
        ).await;
        println!("COMMAND (verack) => {:x?}", std::str::from_utf8(&verack.command));

        // Send Verack message
        self.send(stream,
            &Verack{},
            &Options{version: super::messages::PROTOCOL_VERSION, is_version_message: false},
        ).await.unwrap();
        println!("SENT => Verack");
    }

    async fn send<T: Packet + Serializable>(&self, stream: &mut tokio::net::TcpStream, payload: &T, opt: &Options) -> Result<usize, tokio::io::Error> {
        let message: Message = Message::new(self.network, payload, opt);
        let mut buf: Vec<u8> = Vec::new();
        message.to_wire(&mut buf, &opt);
        stream.write(&buf).await
    }

    async fn receive(&self, stream: &mut tokio::net::TcpStream, opt: &Options) -> Box<Message> {
        let mut buf: Vec<u8> = vec![0; MTU];
        let _result: Result<usize, tokio::io::Error> = stream.read(&mut buf).await;
        Message::parse(&mut buf.as_slice(), &opt)
    }
}
