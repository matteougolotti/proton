use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;
use tokio::prelude::*;

use bitcoin::messages::{
    Getaddr,
    Message,
    Options,
    Packet,
    Serializable,
    Verack,
};
use bitcoin::network::Client;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[tokio::main]
async fn main() -> io::Result<()> {
    let NETWORK = bitcoin::messages::Network::MAINNET;
    // Start listening for connections
/*    let mut listener = TcpListener::bind("127.0.0.1:8333").await?;

    tokio::spawn(async move {
        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            match stream {
                Ok(_stream) => {
                    println!("NEW CLIENT CONNECTED!");
                }
                Err(_e) => { /* connection failed */ }
            }
        }
    });
*/
    // let mut stream: tokio::net::TcpStream = TcpStream::connect("seed.bitcoinstats.com:8333").await.unwrap();
/*    let mut stream: tokio::net::TcpStream = TcpStream::connect("seed.bitcoin.sipa.be:8333").await.unwrap();

    // Build Version message
    let version: bitcoin::messages::Version = bitcoin::messages::Version::new(
        bitcoin::messages::Address::new(stream.local_addr().unwrap().ip()),
        bitcoin::messages::Address::new(stream.peer_addr().unwrap().ip()),
        1,
    );
    // Send Version message
    send(&mut stream,
        NETWORK,
        &version,
        &Options{version: bitcoin::messages::PROTOCOL_VERSION, is_version_message: true},
    ).await.unwrap();

    // Receive Version message
    let msg: Box<Message> = receive(&mut stream,
        &Options{version: bitcoin::messages::PROTOCOL_VERSION, is_version_message: true},
    ).await;
    println!("COMMAND => {:x?}", std::str::from_utf8(&msg.command));

    // Receive Verack message
    let msg: Box<Message> = receive(&mut stream,
        &Options{version: bitcoin::messages::PROTOCOL_VERSION, is_version_message: false},
    ).await;
    println!("COMMAND => {:x?}", std::str::from_utf8(&msg.command));

    // Send Verack message
    let verack: Verack = Verack{};
    send(&mut stream,
        bitcoin::messages::Network::MAINNET,
        &verack,
        &Options{version: bitcoin::messages::PROTOCOL_VERSION, is_version_message: false},
    ).await.unwrap();
    println!("Sent Verack!");
*/
/*    let mut buf: Vec<u8> = Vec::new();
    let getaddr: Getaddr = Getaddr{};
    getaddr.to_wire(&mut buf, &Options{version: bitcoin::messages::PROTOCOL_VERSION, is_version_message: false});
    stream.write_all(&buf).await.unwrap();
    stream.flush();
    println!("Sent Getaddr!");*/

    let client: Client = Client::new(bitcoin::messages::Network::MAINNET);    
    client.start().await;

/*    for _ in 0..1 as usize {
        let mut buf: Vec<u8> = vec![0; 1500];
        let result: Result<usize, tokio::io::Error> = stream.read(&mut buf).await;

        match result {
            Ok(0) => (),
            Ok(_) => {
                let msg: Box<Message> = Message::parse(
                    &mut buf.as_slice(),
                    &Options{version: bitcoin::messages::PROTOCOL_VERSION, is_version_message: false});
                println!("MESSAGE => {:x?}", msg.payload.as_slice());
                println!("COMMAND => {:x?}", std::str::from_utf8(&msg.command));
                ()
            }
            Err(_) => (),
        }
    }
*/
    Ok(())
}
/*
async fn send<T: Packet + Serializable>(stream: &mut tokio::net::TcpStream, network: bitcoin::messages::Network, payload: &T, opt: &Options) -> Result<usize, tokio::io::Error> {
    let message: Message = Message::new(network, payload, opt);
    let mut buf: Vec<u8> = Vec::new();
    message.to_wire(&mut buf, &opt);
    stream.write(&buf).await
}

async fn receive(stream: &mut tokio::net::TcpStream, opt: &Options) -> Box<Message> {
    let mut buf: Vec<u8> = vec![0; MTU];
    let _result: Result<usize, tokio::io::Error> = stream.read(&mut buf).await;
    Message::parse(&mut buf.as_slice(), &opt)
}
*/
