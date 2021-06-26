use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();
    println!("Server bound...");

    loop {
        let (socket, _) = listener.accept().await.unwrap();
        process(socket).await;

        // so that communications are encrypted right away
        establish_key();

        auth();

        // from this point onward the two peers negotiate the various details
        transfer_data_to_peer();
    }
}

async fn process(socket: TcpStream) {
    let mut buf = [0u8; 16];
    socket.try_read(&mut buf);

    println!("{:?}", buf);
}
