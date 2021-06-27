use server::establish_key;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();
    println!("Server bound...");

    loop {
        let (socket, _addr) = listener.accept().await.unwrap();

        tokio::spawn(async move {
            process(socket).await;
        });
    }

    // // so that communications are encrypted right away
    // establish_key();

    // auth();

    // // from this point onward the two peers negotiate the various details
    // transfer_data_to_peer();
}

async fn process(mut socket: TcpStream) {
    let (r, mut w) = socket.split();
    let mut bufread = BufReader::new(r);
    let mut s = String::new();

    loop {
        let n = bufread.read_line(&mut s).await.unwrap();
        if n == 0 {
            break;
        }

        w.write_all(s.as_bytes()).await.unwrap();
        s.clear();
    }
}
