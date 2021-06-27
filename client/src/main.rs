use std::net::TcpStream;
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

fn main() {
    let stream = TcpStream::connect("127.0.0.1:9001").unwrap();

    let client_secret = EphemeralSecret::new(OsRng);
    let client_public = PublicKey::from(&client_secret);

    // send pubkey to server

    // get server's pubkey
    let server_public = get_server_pubkey();

    let shared = client_secret.diffie_hellman(&client_public);
    
    // for debugging puproses only!
    println!("{:?}", shared.as_bytes());
}
