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
pub const USER_AGENT: &str = "/Proton:0.0.1/";
pub const NODE_WITNESS: u64 = 1 << 3;

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum Network {
    MAINNET = 0xD9B4BEF9,
    TESTNET = 0xDAB5BFFA,
}

pub trait Serializable {
    fn parse(stream: &mut dyn Read, opt: &Options) -> Box<Self>;

    fn serialize(&self, stream: &mut dyn Write, opt: &Options);
}

pub struct Options {
    pub version: i32,
    pub is_version_message: bool,
}

#[derive(Debug)]
pub enum BitcoinMessage {
    Version(Version),
    Verack(Verack),
    Ping(Ping),
    Pong(Pong),
    Alert(Alert),
    Addr(Addr),
    Getaddr(Getaddr),
}

impl BitcoinMessage {
    fn command(&self) -> String {
        match self {
            BitcoinMessage::Version(_) => String::from("version"),
            BitcoinMessage::Verack(_) => String::from("verack"),
            BitcoinMessage::Ping(_) => String::from("ping"),
            BitcoinMessage::Pong(_) => String::from("pong"),
            BitcoinMessage::Alert(_) => String::from("alert"),
            BitcoinMessage::Addr(_) => String::from("addr"),
            BitcoinMessage::Getaddr(_) => String::from("getaddr"),
        }
    }
}

pub fn write(message: &BitcoinMessage, stream: &mut Vec<u8>, magic: Network, opt: &Options) {
    let mut command: [u8; 12] = Default::default();

    let cmd: String = message.command();
    let padding: Vec<u8> = vec![0; 12 - cmd.len()];
    command.copy_from_slice(
        [cmd.as_bytes(), padding.as_slice()].concat().as_slice()
    );

    let mut payload: Vec<u8> = Vec::new();
    match message {
        BitcoinMessage::Version(version) => version.serialize(&mut payload, &Options{version: PROTOCOL_VERSION, is_version_message: true}),
        BitcoinMessage::Verack(verack) => verack.serialize(&mut payload, opt),
        BitcoinMessage::Ping(ping) => ping.serialize(&mut payload, opt),
        BitcoinMessage::Pong(pong) => pong.serialize(&mut payload, opt),
        BitcoinMessage::Alert(alert) => alert.serialize(&mut payload, opt),
        BitcoinMessage::Addr(addr) => addr.serialize(&mut payload, opt),
        BitcoinMessage::Getaddr(getaddr) => getaddr.serialize(&mut payload, opt),
    }

    let length: u32 = payload.len() as u32;
    let checksum = checksum(&payload);

    stream.write_u32::<LittleEndian>(magic as u32).unwrap();
    stream.write_all(&command).unwrap();
    stream.write_u32::<LittleEndian>(length).unwrap();
    stream.write_u32::<LittleEndian>(checksum).unwrap();
    stream.write_all(&payload).unwrap();
}

pub fn read(data: &mut [u8], opt: &Options) -> Result<(Box<BitcoinMessage>, usize), ()> {
    static FIXED_HEADER_SIZE: usize = 24;
    let data_len: u32 = data.len() as u32;
    let mut stream = std::io::Cursor::new(data);

    let _magic: u32 = stream.read_u32::<LittleEndian>().unwrap();

    let mut padded_command: [u8; 12] = [0; 12];
    stream.read(&mut padded_command).unwrap();
    let command: Vec<u8> = padded_command
        .iter()
        .take_while(|&&x| x != 0)
        .cloned()
        .collect();

    let length: u32 = stream.read_u32::<LittleEndian>().unwrap();
    let _checksum: u32 = stream.read_u32::<LittleEndian>().unwrap();

    let mut payload: Vec<u8> = vec![0; length as usize];
    stream.read(&mut payload).unwrap();

    let size: usize = FIXED_HEADER_SIZE + length as usize;

    // TODO verify checksum

    match data_len >= length {
        true => {
            match std::str::from_utf8(&command).unwrap() {
                "version" => Ok((
                        Box::new(BitcoinMessage::Version(*Version::parse(
                            &mut payload.as_slice(),
                            &Options{version: opt.version, is_version_message: true}
                        ))),
                        size
                )),
                "verack" => Ok((Box::new(BitcoinMessage::Verack(*Verack::parse(&mut payload.as_slice(), opt))), size)),
                "alert" => Ok((Box::new(BitcoinMessage::Alert(*Alert::parse(&mut payload.as_slice(), opt))), size)),
                "ping" => Ok((Box::new(BitcoinMessage::Ping(*Ping::parse(&mut payload.as_slice(), opt))), size)),
                "pong" => Ok((Box::new(BitcoinMessage::Pong(*Pong::parse(&mut payload.as_slice(), opt))), size)),
                "getaddr" => Ok((Box::new(BitcoinMessage::Getaddr(*Getaddr::parse(&mut payload.as_slice(), opt))), size)),
                "addr" => Ok((Box::new(BitcoinMessage::Addr(*Addr::parse(&mut payload.as_slice(), opt))), size)),
                command => {
                    println!("Unable to process command => {}", command);
                    Err(())
                }
            }
        },
        false => Err(())
    }
}

#[derive(Debug)]
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

    pub fn as_usize(&self) -> usize {
        match self {
            VarInt::U8(n) => *n as usize,
            VarInt::U16(n) => *n as usize,
            VarInt::U32(n) => *n as usize,
            VarInt::U64(n) => *n as usize,
        }
    }
}

impl Serializable for VarInt {
    fn parse(stream: &mut dyn Read, _opt: &Options) -> Box<Self> {
        match stream.read_u8().unwrap() {
            0xFF => Box::new(VarInt::U64(stream.read_u64::<LittleEndian>().unwrap())),
            0xFE => Box::new(VarInt::U32(stream.read_u32::<LittleEndian>().unwrap())),
            0xFD => Box::new(VarInt::U16(stream.read_u16::<LittleEndian>().unwrap())),
            value => Box::new(VarInt::U8(value)),
        }
    }

    fn serialize(&self, stream: &mut dyn Write, _opt: &Options) {
        match self {
            VarInt::U8(n) => stream.write_u8(*n).unwrap(),
            VarInt::U16(n) => {
                stream.write_u8(0xFD).unwrap();
                stream.write_u16::<LittleEndian>(*n).unwrap();
            },
            VarInt::U32(n) => {
                stream.write_u8(0xFE).unwrap();
                stream.write_u32::<LittleEndian>(*n).unwrap();
            },
            VarInt::U64(n) => {
                stream.write_u8(0xFF).unwrap();
                stream.write_u64::<LittleEndian>(*n).unwrap();
            },
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
        let n: usize = length.as_usize();
        let mut buf: Vec<u8> = vec![0; n];
        stream.read(&mut buf).unwrap();
        let string = String::from_utf8(buf).unwrap();

        Box::new(
            Self {
                length: length,
                string: string,
            }
        )
    }

    fn serialize(&self, stream: &mut dyn Write, opt: &Options) {
        self.length.serialize(stream, opt);
        stream.write(self.string.as_bytes()).unwrap();
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct Address {
    pub timestamp: u32,
    pub services: u64,
    pub ip: IpAddr,
    pub port: u16,
}

impl Address {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32,
            services: PROTOCOL_SERVICES,
            ip: ip,
            port: 8333,
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
                u16::from_be_bytes([ipv6[4], ipv6[5]]),
                u16::from_be_bytes([ipv6[6], ipv6[7]]),
                u16::from_be_bytes([ipv6[8], ipv6[9]]),
                u16::from_be_bytes([ipv6[10], ipv6[11]]),
                u16::from_be_bytes([ipv6[12], ipv6[13]]),
                u16::from_be_bytes([ipv6[14], ipv6[15]]),
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

    fn serialize(&self, stream: &mut dyn Write, opt: &Options) {
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

#[derive(Debug)]
pub struct Version {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: Address,
    pub addr_from: Address,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: Option<bool>,
}

impl Version {
    pub fn new(addr_from: Address, addr_recv: Address, services: u64) -> Version {
        let mut rng = rand::thread_rng();

        Self {
            version: PROTOCOL_VERSION,
            services: services,
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64,
            addr_recv: addr_recv,
            addr_from: addr_from,
            nonce: rng.gen(),
            user_agent: String::from(USER_AGENT),
            start_height: 0,
            relay: Some(true),
        }
    }

    pub fn is_segwit(&self) -> bool {
        self.services & NODE_WITNESS != 0
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

    fn serialize(&self, stream: &mut dyn Write, _opt: &Options) {
        stream.write_i32::<LittleEndian>(self.version).unwrap();
        stream.write_u64::<LittleEndian>(self.services).unwrap();
        stream.write_i64::<LittleEndian>(self.timestamp).unwrap();
        self.addr_recv.serialize(stream, &Options{version: 0, is_version_message: true});
        self.addr_from.serialize(stream, &Options{version: 0, is_version_message: true});
        stream.write_u64::<LittleEndian>(self.nonce).unwrap();
        VarString::new(&self.user_agent).serialize(stream, _opt);
        stream.write_i32::<LittleEndian>(self.start_height).unwrap();
        if self.version >= 70001 {
            match self.relay {
                Some(value) => stream.write_u8(value as u8).unwrap(),
                None => stream.write_u8(false as u8).unwrap(),
            }
        }
    }
}

#[derive(Debug)]
pub struct Verack {
}

impl Serializable for Verack {
    fn parse(_stream: &mut dyn Read, _opt: &Options) -> Box<Self> {
        Box::new(Self{})
    }

    fn serialize(&self, _stream: &mut dyn Write, _opt: &Options) {
    }
}

#[derive(Debug)]
pub struct Addr {
    pub count: VarInt,
    pub addr_list: Vec<Address>,
}

impl Serializable for Addr {
    fn parse(stream: &mut dyn Read, opt: &Options) -> Box<Self> {
        let count: VarInt = *VarInt::parse(stream, &opt);
        let mut addr_list: Vec<Address> = Vec::new();

        for _ in 0..count.as_usize() {
            let addr: Address = *Address::parse(stream, &opt);
            addr_list.push(addr);
        }

        Box::new(
            Self{
                count: count,
                addr_list: addr_list,
            }
        )
    }

    fn serialize(&self, stream: &mut dyn Write, opt: &Options) {
        self.count.serialize(stream, opt);
        for addr in self.addr_list.iter() {
            addr.serialize(stream, opt);
        }
    }
}

#[derive(Debug)]
pub struct Alert {
    // Alerts have been decommissioned, so we fake parsing
}

impl Serializable for Alert {
    fn parse(_stream: &mut dyn Read, _opt: &Options) -> Box<Self> {
        Box::new(
            Self{
            }
        )
    }

    fn serialize(&self, _stream: &mut dyn Write, _opt: &Options) {
        panic!("Not implemented");
    }
}

#[derive(Debug)]
pub struct Ping {
    pub nonce: u64,
}

impl Serializable for Ping {
    fn parse(stream: &mut dyn Read, _opt: &Options) -> Box<Self> {
        Box::new(
            Self{
                nonce: stream.read_u64::<LittleEndian>().unwrap(),
            }
        )
    }

    fn serialize(&self, stream: &mut dyn Write, _opt: &Options) {
        stream.write_u64::<LittleEndian>(self.nonce).unwrap();
    }
}

#[derive(Debug)]
pub struct Pong {
    pub nonce: u64,
}

impl Serializable for Pong {
    fn parse(stream: &mut dyn Read, _opt: &Options) -> Box<Self> {
        Box::new(
            Self{
                nonce: stream.read_u64::<LittleEndian>().unwrap(),
            }
        )
    }

    fn serialize(&self, stream: &mut dyn Write, _opt: &Options) {
        stream.write_u64::<LittleEndian>(self.nonce).unwrap();
    }
}

#[derive(Debug)]
pub struct Getaddr {
}

impl Serializable for Getaddr {
    fn parse(_stream: &mut dyn Read, _opt: &Options) -> Box<Self> {
        Box::new(Self{})
    }

    fn serialize(&self, _stream: &mut dyn Write, _opt: &Options) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_u8() {
        let expected: u8 = 12;
        let n: VarInt = VarInt::U8(expected);
        let opt: Options = Options{
            version: super::PROTOCOL_VERSION,
            is_version_message: true,
        };

        let mut buf: Vec<u8> = Vec::new();
        n.serialize(&mut buf, &opt);

        let mut buf = buf.as_slice();
        let n: Box<VarInt> = VarInt::parse(&mut buf, &opt);

        match *n {
            VarInt::U8(number) => assert_eq!(expected, number),
            _ => panic!(),
        }
    }

    #[test]
    fn test_varint_u16() {
        let expected: u16 = 0xFFFA;
        let n: VarInt = VarInt::U16(expected);
        let opt: Options = Options{
            version: super::PROTOCOL_VERSION,
            is_version_message: true,
        };

        let mut buf: Vec<u8> = Vec::new();
        n.serialize(&mut buf, &opt);

        let mut buf = buf.as_slice();
        let n: Box<VarInt> = VarInt::parse(&mut buf, &opt);

        match *n {
            VarInt::U16(number) => assert_eq!(expected, number),
            _ => panic!(),
        }
    }

    #[test]
    fn test_varint_u32() {
        let expected: u32 = 0xFFFA;
        let n: VarInt = VarInt::U32(expected);
        let opt: Options = Options{
            version: super::PROTOCOL_VERSION,
            is_version_message: true,
        };

        let mut buf: Vec<u8> = Vec::new();
        n.serialize(&mut buf, &opt);

        let mut buf = buf.as_slice();
        let n: Box<VarInt> = VarInt::parse(&mut buf, &opt);

        match *n {
            VarInt::U32(number) => assert_eq!(expected, number),
            _ => panic!(),
        }
    }

    #[test]
    fn test_varint_u64() {
        let expected: u64 = 0xFFFFFA;
        let n: VarInt = VarInt::U64(expected);
        let opt: Options = Options{
            version: super::PROTOCOL_VERSION,
            is_version_message: true,
        };

        let mut buf: Vec<u8> = Vec::new();
        n.serialize(&mut buf, &opt);

        let mut buf = buf.as_slice();
        let n: Box<VarInt> = VarInt::parse(&mut buf, &opt);

        match *n {
            VarInt::U64(number) => assert_eq!(expected, number),
            _ => panic!(),
        }
    }

    #[test]
    fn test_varstring() {
        let expected: String = String::from("Test");
        let s: VarString = VarString::new(&expected);
        let opt: Options = Options{version: super::PROTOCOL_VERSION, is_version_message: true};

        let mut buf: Vec<u8> = Vec::new();
        s.serialize(&mut buf, &opt);

        let mut buf = buf.as_slice();
        let s: Box<VarString> = VarString::parse(&mut buf, &opt);

        assert_eq!(expected, s.string);
    }

    #[test]
    fn test_address_ipv4_version_message() {
        let expected_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let expected_address: Address = Address::new(expected_ip);
        let expected_timestamp: u32 = 0;
        let opt: Options = Options{version: super::PROTOCOL_VERSION, is_version_message: true};

        let mut buf: Vec<u8> = Vec::new();
        expected_address.serialize(&mut buf, & opt);

        let mut buf = buf.as_slice();
        let address: Box<Address> = Address::parse(&mut buf, &opt);

        assert_eq!(expected_ip, address.ip, "IP addresses");
        assert_eq!(expected_address.port, address.port, "Port");
        assert_eq!(expected_address.services, address.services, "Services");
        assert_eq!(expected_timestamp, address.timestamp, "Timestamp");
    }

    #[test]
    fn test_address_ipv4() {
        let expected_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let expected_address: Address = Address::new(expected_ip);
        let opt: Options = Options{version: super::PROTOCOL_VERSION, is_version_message: false};

        let mut buf: Vec<u8> = Vec::new();
        expected_address.serialize(&mut buf, & opt);

        let mut buf = buf.as_slice();
        let address: Box<Address> = Address::parse(&mut buf, &opt);

        assert_eq!(expected_ip, address.ip, "IP addresses");
        assert_eq!(expected_address.port, address.port, "Port");
        assert_eq!(expected_address.services, address.services, "Services");
        assert_eq!(expected_address.timestamp, address.timestamp, "Timestamp");
    }

    #[test]
    fn test_version() {
        let expected: Version = Version::new(
            Address::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            Address::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))),
            super::PROTOCOL_SERVICES,
        );
        let opt: Options = Options{version: super::PROTOCOL_VERSION, is_version_message: true};

        let mut buf: Vec<u8> = Vec::new();
        expected.serialize(&mut buf, &opt);

        let mut buf = buf.as_slice();
        let version: Box<Version> = Version::parse(&mut buf, &opt);

        assert_eq!(expected.version, version.version);
        assert_eq!(expected.services, version.services);
        assert_eq!(expected.timestamp, version.timestamp);
        assert_eq!(expected.nonce, version.nonce);
        assert_eq!(expected.addr_recv.ip, version.addr_recv.ip);
        assert_eq!(expected.addr_from.ip, version.addr_from.ip);
        assert_eq!(expected.user_agent, version.user_agent);
        assert_eq!(expected.start_height, version.start_height);
    }

    #[test]
    fn test_addr_message() {
        let opt: Options = Options{version: super::PROTOCOL_VERSION, is_version_message: false};
        let mut addr_list: Vec<Address> = Vec::new();
        let address: Address = Address::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        addr_list.push(address);
        let count: VarInt = VarInt::U8(1);
        let expected: Addr = Addr{count: count, addr_list: addr_list};

        let mut buf: Vec<u8> = Vec::new();
        expected.serialize(&mut buf, &opt);

        let mut buf = buf.as_slice();
        let addr: Box<Addr> = Addr::parse(&mut buf, &opt);

        assert_eq!(expected.count.as_usize(), addr.count.as_usize());
        assert_eq!(expected.addr_list[0].ip, addr.addr_list[0].ip);
        assert_eq!(expected.addr_list[0].port, addr.addr_list[0].port);
    }
}
