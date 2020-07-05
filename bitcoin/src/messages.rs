// Docs
// https://en.bitcoin.it/wiki/Protocol_documentation

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;

use crate::utils::{checksum};

pub const PROTOCOL_SERVICES: u64 = 9;
pub const PROTOCOL_VERSION: i32 = 70001;
pub const USER_AGENT: &str = "/Muon:0.0.1/";
pub const NODE_WITNESS: u64 = 1 << 3;

#[repr(u32)]
pub enum Network {
    MAINNET = 0xD9B4BEF9,
    TESTNET = 0xDAB5BFFA,
}

pub trait Packet {
    fn command(&self) -> String;
}

pub trait Serializable {
    fn parse(stream: &mut dyn Read, opt: &Options) -> Box<Self>;

    fn to_wire(&self, stream: &mut dyn Write, opt: &Options);
}

pub struct Options {
    pub version: i32,
    pub is_version_message: bool,
}

pub struct Message {
    pub magic: u32,
    pub command: [u8; 12],
    pub length: u32,
    pub checksum: u32,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new<T: Packet + Serializable>(magic: Network, payload_msg: &T, opt: &Options) -> Message {
        let mut cmd: [u8; 12] = Default::default();

        let command: String = payload_msg.command();
        let padding: Vec<u8> = vec![0; 12 - command.len()];
        cmd.copy_from_slice(
            [command.as_bytes(), padding.as_slice()].concat().as_slice()
        );

        let mut payload: Vec<u8> = Vec::new();
        payload_msg.to_wire(&mut payload, opt);

        Self {
            magic: magic as u32,
            command: cmd,
            length: payload.len() as u32,
            checksum: checksum(&payload),
            payload: payload,
        }
    }
}

impl Serializable for Message {
    fn parse(stream: &mut dyn Read, _opt: &Options) -> Box<Self> {
        let magic: u32 = stream.read_u32::<LittleEndian>().unwrap();
        
        let mut padded_command: [u8; 12] = [0; 12];
        stream.read(&mut padded_command).unwrap();
        let _command: Vec<u8> = padded_command
            .iter()
            .take_while(|&&x| x != 0)
            .cloned()
            .collect();
        
        let length: u32 = stream.read_u32::<LittleEndian>().unwrap();
        let checksum: u32 = stream.read_u32::<LittleEndian>().unwrap();

        let mut payload: Vec<u8> = Vec::new();
        stream.read(&mut payload).unwrap();

        Box::new(
            Self {
                magic: magic,
                command: padded_command,
                length: length,
                checksum: checksum,
                payload: payload,
            }
        )
    }

    fn to_wire(&self, stream: &mut dyn Write, _opt: &Options) {
        stream.write_u32::<LittleEndian>(self.magic).unwrap();
        stream.write(&self.command).unwrap();
        stream.write_u32::<LittleEndian>(self.length).unwrap();
        stream.write_u32::<LittleEndian>(self.checksum).unwrap();
        stream.write(&self.payload).unwrap();
    }
}

pub enum VarInt {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

impl VarInt {
    fn new(n: usize) -> Self {
        if n < 0xFD {
            VarInt::U8(n as u8)
        } else if n < 0xFE {
            VarInt::U16(n as u16)
        } else if n < 0xFF {
            VarInt::U32(n as u32)
        } else {
            VarInt::U64(n as u64)
        }
    }
}

impl Serializable for VarInt {
    fn parse(stream: &mut dyn Read, _opt: &Options) -> Box<Self> {
        match stream.read_u8().unwrap() {
            0xFF => Box::new(VarInt::U64(stream.read_u64::<LittleEndian>().unwrap())),
            0xFE => Box::new(VarInt::U32(stream.read_u32::<LittleEndian>().unwrap())),
            0xFD => Box::new(VarInt::U16(stream.read_u16::<LittleEndian>().unwrap())),
            _ => Box::new(VarInt::U8(stream.read_u8().unwrap())),
        }
    }

    fn to_wire(&self, stream: &mut dyn Write, _opt: &Options) {
        match self {
            VarInt::U8(n) => stream.write_u8(*n).unwrap(),
            VarInt::U16(n) => stream.write_u16::<LittleEndian>(*n).unwrap(),
            VarInt::U32(n) => stream.write_u32::<LittleEndian>(*n).unwrap(),
            VarInt::U64(n) => stream.write_u64::<LittleEndian>(*n).unwrap(),
        }
    }
}

pub struct VarString {
    pub length: VarInt,
    pub string: String,
}

impl VarString {
    fn new(string: &String) -> Self {
        VarString {
            length: VarInt::new(string.len()),
            string: string.clone(),
        }
    }
}

impl Serializable for VarString {
    fn parse(stream: &mut dyn Read, opt: &Options) -> Box<Self> {
        let length: VarInt = *VarInt::parse(stream, opt);
        let string: String = match length {
            VarInt::U8(n) => {
                let mut buf: Vec<u8> = vec![0; n as usize];
                stream.read(&mut buf).unwrap();
                String::from_utf8(buf).unwrap()
            },
            VarInt::U16(n) => {
                let mut buf: Vec<u8> = vec![0; n as usize];
                stream.read(&mut buf).unwrap();
                String::from_utf8(buf).unwrap()
            },
            VarInt::U32(n) => {
                let mut buf: Vec<u8> = vec![0; n as usize];
                stream.read(&mut buf).unwrap();
                String::from_utf8(buf).unwrap()
            },
            VarInt::U64(n) => {
                let mut buf: Vec<u8> = vec![0; n as usize];
                stream.read(&mut buf).unwrap();
                String::from_utf8(buf).unwrap()
            },
        };

        Box::new(
            Self {
                length: *VarInt::parse(stream, opt),
                string: string,
            }
        )
    }

    fn to_wire(&self, stream: &mut dyn Write, opt: &Options) {
        self.length.to_wire(stream, opt);
        stream.write(self.string.as_bytes()).unwrap();
    }
}

pub struct Address {
    pub ip: IpAddr,
    pub port: u16,
    pub services: u64,
    pub timestamp: u32,
}

impl Address {
    pub fn new(ip: IpAddr) -> Address {
        Self {
            ip: ip,
            port: 8333,
            services: PROTOCOL_SERVICES,
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32,
        }
    }
}

impl Serializable for Address {
    fn parse(stream: &mut dyn Read, opt: &Options) -> Box<Self> {
        let timestamp: u32 = match opt.version >= 31402 && !opt.is_version_message {
            true => stream.read_u32::<LittleEndian>().unwrap(),
            false => 0 as u32,
        };

        let services = stream.read_u64::<LittleEndian>().unwrap();
        
        let mut encoded_ip: [u8; 16] = [0; 16];
        stream.read(&mut encoded_ip).unwrap();

        let ip: IpAddr = match encoded_ip {
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, a, b, c, d] => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            ipv6 => IpAddr::V6(Ipv6Addr::new(
                u16::from_be_bytes([ipv6[0], ipv6[1]]),
                u16::from_be_bytes([ipv6[2], ipv6[3]]),
                u16::from_be_bytes([ipv6[0], ipv6[1]]),
                u16::from_be_bytes([ipv6[0], ipv6[1]]),
                u16::from_be_bytes([ipv6[0], ipv6[1]]),
                u16::from_be_bytes([ipv6[0], ipv6[1]]),
                u16::from_be_bytes([ipv6[0], ipv6[1]]),
                u16::from_be_bytes([ipv6[0], ipv6[1]]),
            )),
        };

        let port: u16 = stream.read_u16::<BigEndian>().unwrap();

        Box::new(
            Self {
                timestamp: timestamp,
                services: services,
                ip: ip,
                port: port,
            }
        )
    }

    fn to_wire(&self, stream: &mut dyn Write, opt: &Options) {
        if opt.version >= 31402 && !opt.is_version_message {
            stream.write_u32::<LittleEndian>(self.timestamp).unwrap();
        }
        stream.write_u64::<LittleEndian>(self.services).unwrap();
        match self.ip {
            IpAddr::V4(ipv4_addr) => {
                let [a, b, c, d] = ipv4_addr.octets();
                stream.write(
                    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, a, b, c, d],
                ).unwrap();
            },
            IpAddr::V6(ipv6_addr) => {
                stream.write(&ipv6_addr.octets()).unwrap();
            },
        };
        stream.write_u16::<BigEndian>(self.port).unwrap();
    }
}

pub struct Version {
    pub timestamp: i64,
    pub services: u64,
    pub version: i32,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub addr_from: Address,
    pub addr_recv: Address,
    pub relay: Option<bool>,
}

impl Version {
    pub fn new(addr_from: Address, addr_recv: Address, services: u64) -> Version {
        let mut rng = rand::thread_rng();

        Self {
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64,
            services: services,
            version: PROTOCOL_VERSION,
            nonce: rng.gen(),
            user_agent: String::from(USER_AGENT),
            start_height: 0,
            relay: Some(true),
            addr_from: addr_from,
            addr_recv: addr_recv,
        }
    }

    pub fn is_segwit(&self) -> bool {
        self.services & NODE_WITNESS != 0
    }
}

impl Packet for Version {
    fn command(&self) -> String {
        String::from("version")
    }
}

impl Serializable for Version {
    fn parse(stream: &mut dyn Read, _opt: &Options) -> Box<Self> {
        let opt: Options = Options {
            version: PROTOCOL_VERSION,
            is_version_message: true,
        };
        let version: i32 = stream.read_i32::<LittleEndian>().unwrap();
        let services: u64 = stream.read_u64::<LittleEndian>().unwrap();
        let timestamp: i64 = stream.read_i64::<LittleEndian>().unwrap();
        let addr_recv: Address = *Address::parse(stream, &opt);
        let addr_from: Address = *Address::parse(stream, &opt);
        let nonce: u64 = stream.read_u64::<LittleEndian>().unwrap();
        let user_agent: String = VarString::parse(stream, &opt).string;
        let start_height: i32 = stream.read_i32::<LittleEndian>().unwrap();
        let relay: Option<bool> = match version >= 70001 {
            true => Some(stream.read_u8().unwrap() != 0),
            false => None,
        };

        Box::new(
            Self {
                version: version,
                services: services,
                timestamp: timestamp,
                addr_recv: addr_recv,
                addr_from: addr_from,
                nonce: nonce,
                user_agent: user_agent,
                start_height: start_height,
                relay: relay,
            }
        )
    }

    fn to_wire(&self, stream: &mut dyn Write, _opt: &Options) {
        stream.write_i32::<LittleEndian>(self.version).unwrap();
        stream.write_u64::<LittleEndian>(self.services).unwrap();
        stream.write_i64::<LittleEndian>(self.timestamp).unwrap();
        self.addr_recv.to_wire(stream, &Options{version: 0, is_version_message: true});
        self.addr_from.to_wire(stream, &Options{version: 0, is_version_message: true});
        stream.write_u64::<LittleEndian>(self.nonce).unwrap();
        VarString::new(&self.user_agent).to_wire(stream, _opt);
        stream.write_i32::<LittleEndian>(self.start_height).unwrap();
        if self.version >= 70001 {
            match self.relay {
                Some(value) => stream.write_u8(value as u8).unwrap(),
                None => stream.write_u8(false as u8).unwrap(),
            }
        }
    }
}

pub struct Verack {
}

impl Packet for Verack {
    fn command(&self) -> String {
        String::from("verack")
    }
}

