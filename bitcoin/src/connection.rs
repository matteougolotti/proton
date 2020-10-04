use std::net::{IpAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};

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

#[derive(Debug)]
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
}

impl Connection {
    pub fn new(id: ConnectionId, peer: String, network: Network, version: i32) -> Self {
        Self {
            id: id,
            peer: peer,
            network: network,
        }
    }

    pub async fn run(&self, mut rx: Receiver<Message>, mut tx: Sender<Message>) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(&self.peer).await.unwrap();

        let opt: Options = Options{version: super::messages::PROTOCOL_VERSION, is_version_message: true};
        let local_addr: IpAddr = stream.local_addr().unwrap().ip();
        let peer_addr: IpAddr = stream.peer_addr().unwrap().ip();

        self.send(&mut stream, &BitcoinMessage::Version(Version::new(Address::new(local_addr), Address::new(peer_addr), 1)), &opt).await?;
        println!("SENT => Version");

        let opt: Options = Options{version: super::messages::PROTOCOL_VERSION, is_version_message: false};
        let mut parse_buff: Vec<u8> = Vec::new();
        let mut read_buff: Vec<u8> = vec![0; MTU];

        loop {
            tokio::select! {
                message = rx.recv() => {
                    match message {
                        Some(Message::Disconnect) => self.disconnect(&mut stream).await?,
                        Some(Message::OutgoingBitcoinMessage(message)) => {
                            self.send(&mut stream, &message, &Options{version: super::messages::PROTOCOL_VERSION, is_version_message: false}).await?;
                        },
                        _ => (),
                    }
                }
                bitcoin_message = stream.read(&mut read_buff) => {
                    match bitcoin_message {
                        Ok(bytes_read) if bytes_read > 0 || parse_buff.len() > 0 => {
                            println!("Read {} bytes", bytes_read);
                            println!("Read buff => {:x?}", read_buff);
                            parse_buff.extend_from_slice(&mut read_buff[0..bytes_read]);
                            println!("Extended vector");
                            println!("Parse buff => {:x?}", parse_buff.as_slice());
                            match super::messages::read(&mut parse_buff, &opt) {
                                Ok((message, n)) => {
                                    println!("Parsed {} bytes", n);
                                    self.handle_bitcoin_message(*message, &mut stream, &mut tx).await?;
                                    parse_buff.drain(0..n);
                                },
                                Err(_) => {
                                    println!("Parsing error!");
                                }
                            }
                        },
                        Ok(_) => (),
                        Err(_) => {
                            tx.send(Message::Disconnected(self.id)).await?;
                            self.disconnect(&mut stream).await?
                        }
                    }
                }
            }
        }
    }

    async fn disconnect(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        stream.shutdown().await?;
        Ok(())
    }

    async fn handle_bitcoin_message(&self, message: BitcoinMessage, stream: &mut TcpStream, tx: &mut Sender<Message>) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let opt: Options = Options{version: super::messages::PROTOCOL_VERSION, is_version_message: false};

        match message {
            BitcoinMessage::Version(_version) => {
                println!("RECEIVED => version");
                Ok(())
            },
            BitcoinMessage::Verack(_verack) => {
                println!("RECEIVED => verack");
                self.send(stream, &BitcoinMessage::Verack(Verack{}), &opt).await?;
                Ok(())
            },
            BitcoinMessage::Alert(_alert) => {
                println!("RECEIVED => alert");
                Ok(())
            },
            BitcoinMessage::Ping(ping) => {
                println!("RECEIVED => ping {}", ping.nonce);
                let pong: Pong = Pong{nonce: ping.nonce};
                self.send(stream, &BitcoinMessage::Pong(pong), &opt).await?;
                println!("SENT => pong {}", ping.nonce);
                Ok(())
            },
            BitcoinMessage::Pong(pong) => {
                println!("RECEIVED => pong {}", pong.nonce);
                Ok(())
            },
            _ => {
                tx.send(Message::IncomingBitcoinMessage((self.id, message))).await?;
                Ok(())
            },
        }
    }

    async fn send(&self, stream: &mut TcpStream, message: &BitcoinMessage, opt: &Options) -> std::result::Result<(), std::io::Error> {
        let mut buf: Vec<u8> = Vec::new();
        super::messages::write(message, &mut buf, self.network, opt);
        stream.write_all(&buf).await
    }
}
