use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, Shutdown};

use super::messages::{
    Address,
    Command,
    Message,
    Network,
    Options,
    Pong,
    Serializable,
    Verack,
    Version,
};

const MTU: usize = 1500;

pub struct Connection {
    pub peer: String,
    pub network: Network,
    pub version: Cell<i32>,
    stop: std::sync::RwLock<bool>,
}

impl Connection {
    pub fn new(peer: String, network: Network, version: i32) -> Self {
        Self{
            peer: peer,
            network: network,
            version: Cell::new(version),
            stop: std::sync::RwLock::new(false),
        }
    }

    pub fn connect(&self) -> std::io::Result<()> {
        self.version.set(super::messages::PROTOCOL_VERSION);
        let mut stream = TcpStream::connect(&self.peer)?;

        self.init_connection(&mut stream);

        self.run(&mut stream);

        Ok(())
    }

    pub fn disconnect(&self) {
        let mut stop = self.stop.write().unwrap();
        *stop = true;
    }

    fn init_connection(&self, stream: &mut TcpStream) {
        let opt: Options = Options{version: super::messages::PROTOCOL_VERSION, is_version_message: true};
        let local_addr: IpAddr = stream.local_addr().unwrap().ip();
        let peer_addr: IpAddr = stream.peer_addr().unwrap().ip();

        self.send(stream, &Version::new(Address::new(local_addr), Address::new(peer_addr), 1), &opt);
        println!("SENT => Version");
    }

    fn run(&self, stream: &mut TcpStream) {
        let opt: Options = Options{version: self.version.get(), is_version_message: false};
        let mut parse_buff: Vec<u8> = Vec::new();
        let mut read_buff: Vec<u8> = vec![0; MTU];

        while !(*self.stop.read().unwrap()) {
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
                            self.handle_message(&message, stream);
                            parse_buff.drain(0..n);
                        },
                        Err(_) => {
                            println!("Parsing error!");
                        }
                    }
                },
                Ok(_) => (),
                Err(_) => {
                    stream.shutdown(Shutdown::Both).unwrap();
                    break;
                }
            }
        }

        stream.shutdown(Shutdown::Both).unwrap();
    }

    fn handle_message(&self, message: &Message, stream: &mut TcpStream) {
        let opt: Options = Options{version: super::messages::PROTOCOL_VERSION, is_version_message: false};

        match message {
            Message::Version(version) => {
                println!("RECEIVED => version");
                self.version.set(std::cmp::min(super::messages::PROTOCOL_VERSION, version.version));
            },
            Message::Verack(_verack) => {
                println!("RECEIVED => verack");
                self.send(stream, &Verack{}, &opt);
            },
            Message::Alert(_alert) => {
                println!("RECEIVED => alert");
            },
            Message::Ping(ping) => {
                println!("RECEIVED => ping {}", ping.nonce);
                let pong: Pong = Pong{nonce: ping.nonce};
                self.send(stream, &pong, &opt);
                println!("SENT => pong {}", pong.nonce);
            },
            Message::Pong(pong) => {
                println!("RECEIVED => pong {}", pong.nonce);
            }
        }
    }

    fn send<T: Command + Serializable>(&self, stream: &mut dyn Write, message: &T, opt: &Options) {
        super::messages::write(message, stream, self.network, opt);
    }
}
