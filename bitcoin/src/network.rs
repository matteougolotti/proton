use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, Shutdown};

use super::messages::{
    Address,
    Command,
    Message,
    Network,
    Options,
    Serializable,
    Verack,
    Version,
};

const MTU: usize = 1500;

pub struct Connection {
    pub peer: String,
    pub network: Network,
    pub version: Cell<i32>,
    pub stop: std::sync::RwLock<bool>,
}

impl Connection {
    pub fn connect(&self) -> std::io::Result<()> {
        self.version.set(super::messages::PROTOCOL_VERSION);
        let mut stream = TcpStream::connect(&self.peer)?;

        self.init_connection(&mut stream);

        self.run(&mut stream);

        Ok(())
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
                Ok(n) if n > 0 => {
                    println!("Read {} bytes", n);
                    println!("Read buff => {:x?}", read_buff);
                    parse_buff.extend_from_slice(&mut read_buff[0..n]);
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
                println!("RECEIVED => Version");
                self.version.set(std::cmp::min(super::messages::PROTOCOL_VERSION, version.version));
            },
            Message::Verack(_verack) => {
                println!("RECEIVED => Verack");
                self.send(stream, &Verack{}, &opt);
            }
        }
    }

    fn send<T: Command + Serializable>(&self, stream: &mut dyn Write, message: &T, opt: &Options) {
        super::messages::write(message, stream, self.network, opt);
    }
}
