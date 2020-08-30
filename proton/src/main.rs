use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;
use tokio::prelude::*;

use bitcoin::messages::{
    Message,
    Options,
    Serializable,
    Verack,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    // Start listening for connections
    let mut listener = TcpListener::bind("127.0.0.1:8333").await?;

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

    let mut stream: tokio::net::TcpStream = TcpStream::connect("seed.bitcoinstats.com:8333").await.unwrap();

    // Build Version message
    let opt: Options = Options{
        version: bitcoin::messages::PROTOCOL_VERSION,
        is_version_message: true,
    };
    let version: bitcoin::messages::Version = bitcoin::messages::Version::new(
        bitcoin::messages::Address::new(stream.local_addr().unwrap().ip()),
        bitcoin::messages::Address::new(stream.peer_addr().unwrap().ip()),
        1,
    );
    let version_msg = bitcoin::messages::Message::new(bitcoin::messages::Network::MAINNET, &version, &opt);

    // Send Version message
    let mut msg: Vec<u8> = Vec::new();
    version_msg.to_wire(&mut msg, &opt);
    stream.write(&msg).await.unwrap();
    println!("Sent version {:x?}", msg.as_slice());

    // Receive Version message
    let mut buf: Vec<u8> = vec![0; 1500];
    let _result: Result<usize, tokio::io::Error> = stream.read(&mut buf).await;
    let msg: Box<Message> = Message::parse(&mut buf.as_slice(), &opt);
    println!("COMMAND => {:x?}", std::str::from_utf8(&msg.command));

    // Receive Verack message
    let mut buf: Vec<u8> = vec![0; 1500];
    let _result: Result<usize, tokio::io::Error> = stream.read(&mut buf).await;
    let msg: Box<Message> = Message::parse(&mut buf.as_slice(), &opt);
    println!("COMMAND => {:x?}", std::str::from_utf8(&msg.command));

    // Send Verack message
    let mut buf: Vec<u8> = Vec::new();
    let verack: Verack = Verack{};
    verack.to_wire(&mut buf, &Options{version: bitcoin::messages::PROTOCOL_VERSION, is_version_message: false});
    stream.write(&buf).await.unwrap();

    loop {
        let mut buf: Vec<u8> = vec![0; 1500];
        let result: Result<usize, tokio::io::Error> = stream.read(&mut buf).await;

        match result {
            Ok(0) => (),
            Ok(_) => {
                let msg: Box<Message> = Message::parse(&mut buf.as_slice(), &opt);
                println!("MESSAGE => {:x?}", msg.payload.as_slice());
                println!("COMMAND => {:x?}", msg.command);
                ()
            }
            Err(_) => (),
        }
    }
}
