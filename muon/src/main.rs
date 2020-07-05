use tokio::net::TcpStream;
use tokio::prelude::*;

use bitcoin::messages::{Options, Serializable};

#[tokio::main]
async fn main() {
    let mut stream = TcpStream::connect("seed.bitcoinstats.com:8333").await.unwrap();
    println!("created Bitcoin stream");

    let version: bitcoin::messages::Version = bitcoin::messages::Version::new(
        bitcoin::messages::Address::new(
            stream.local_addr().unwrap().ip(),
        ),
        bitcoin::messages::Address::new(
            stream.peer_addr().unwrap().ip(),
        ),
        1,
    );

    println!("Building message");
    let version_msg = bitcoin::messages::Message::new(
        bitcoin::messages::Network::MAINNET,
        &version,
        &Options {
            version: bitcoin::messages::PROTOCOL_VERSION,
            is_version_message: true,
        },
    );

    println!("Serializing message");
    let mut msg: Vec<u8> = Vec::new();
    version_msg.to_wire(
        &mut msg,
        &Options {
            version: bitcoin::messages::PROTOCOL_VERSION,
            is_version_message: true,
        }
    );

    println!("Sending message");
    stream.write(&msg).await.unwrap();
    println!("Sent version {:x?}", msg.as_slice());

    println!("Sending verack");
    let mut ack_version: Vec<u8> = Vec::new();
    let _ = stream.read(&mut ack_version).await;
    println!("{:x?}", ack_version.as_slice());
}
