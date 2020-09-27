use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, Shutdown};
use std::sync::mpsc::{Receiver, Sender};

use super::messages::{
    Address,
    BitcoinMessage,
    Network,
    Options,
    Pong,
    Verack,
    Version,
};

const MTU: usize = 1500;

pub type ConnectionId = u32;

pub enum Message {
    IncomingBitcoinMessage((ConnectionId, BitcoinMessage)),
    OutgoingBitcoinMessage(BitcoinMessage),
    Disconnected(ConnectionId),
    Disconnect,
}

pub struct Connection {
    pub id: ConnectionId,
    pub peer: String,
    pub network: Network,
    pub version: Cell<i32>,
    rx: Receiver<Message>,
    tx: Sender<Message>,
}

impl Connection {
    pub fn new(id: ConnectionId, peer: String, network: Network, version: i32, rx: Receiver<Message>, tx: Sender<Message>) -> Self {
        Self {
            id: id,
            peer: peer,
            network: network,
            version: Cell::new(version),
            rx: rx,
            tx: tx,
        }
    }

    pub fn connect(&self) -> std::io::Result<()> {
        self.version.set(super::messages::PROTOCOL_VERSION);
        let mut stream = TcpStream::connect(&self.peer)?;

        self.run(&mut stream);

        Ok(())
    }

    fn run(&self, stream: &mut TcpStream) {
        let opt: Options = Options{version: super::messages::PROTOCOL_VERSION, is_version_message: true};
        let local_addr: IpAddr = stream.local_addr().unwrap().ip();
        let peer_addr: IpAddr = stream.peer_addr().unwrap().ip();

        self.send(stream, &BitcoinMessage::Version(Version::new(Address::new(local_addr), Address::new(peer_addr), 1)), &opt);
        println!("SENT => Version");

        let opt: Options = Options{version: self.version.get(), is_version_message: false};
        let mut parse_buff: Vec<u8> = Vec::new();
        let mut read_buff: Vec<u8> = vec![0; MTU];

        loop {
            match self.rx.try_recv() {
                Ok(Message::Disconnect) => break,
                Ok(Message::OutgoingBitcoinMessage(message)) => {
                    self.send(stream, &message, &Options{version: super::messages::PROTOCOL_VERSION, is_version_message: false});
                },
                _ => (),
            }

            match stream.read(&mut read_buff) {
                Ok(bytes_read) if bytes_read > 0 || parse_buff.len() > 0 => {
                    println!("Read {} bytes", bytes_read);
                    println!("Read buff => {:x?}", read_buff);
                    parse_buff.extend_from_slice(&mut read_buff[0..bytes_read]);
                    println!("Extended vector");
                    println!("Parse buff => {:x?}", parse_buff.as_slice());
                    match super::messages::read(&mut parse_buff, &opt) {
                        Ok((message, n)) => {
                            println!("Parsed {} bytes", n);
                            self.handle_bitcoin_message(*message, stream);
                            parse_buff.drain(0..n);
                        },
                        Err(_) => {
                            println!("Parsing error!");
                        }
                    }
                },
                Ok(_) => (),
                Err(_) => {
                    self.tx.send(Message::Disconnected(self.id)).unwrap();
                    break;
                }
            }
        }

        stream.shutdown(Shutdown::Both).unwrap();
    }

    fn handle_bitcoin_message(&self, message: BitcoinMessage, stream: &mut TcpStream) {
        let opt: Options = Options{version: super::messages::PROTOCOL_VERSION, is_version_message: false};

        match message {
            BitcoinMessage::Version(version) => {
                println!("RECEIVED => version");
                self.version.set(std::cmp::min(super::messages::PROTOCOL_VERSION, version.version));
            },
            BitcoinMessage::Verack(_verack) => {
                println!("RECEIVED => verack");
                self.send(stream, &BitcoinMessage::Verack(Verack{}), &opt);
            },
            BitcoinMessage::Alert(_alert) => {
                println!("RECEIVED => alert");
            },
            BitcoinMessage::Ping(ping) => {
                println!("RECEIVED => ping {}", ping.nonce);
                let pong: Pong = Pong{nonce: ping.nonce};
                self.send(stream, &BitcoinMessage::Pong(pong), &opt);
                println!("SENT => pong {}", ping.nonce);
            },
            BitcoinMessage::Pong(pong) => {
                println!("RECEIVED => pong {}", pong.nonce);
            },
            _ => self.tx.send(Message::IncomingBitcoinMessage((self.id, message))).unwrap()
        }
    }

    fn send(&self, stream: &mut dyn Write, message: &BitcoinMessage, opt: &Options) {
        let mut buf: Vec<u8> = Vec::new();
        super::messages::write(message, &mut buf, self.network, opt);
        stream.write_all(&buf).unwrap();
    }
}
