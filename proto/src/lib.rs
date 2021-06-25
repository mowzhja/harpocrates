/// Struct containing all the data relating to a single packet.
#[derive(Debug)]
struct Packet {
    raw: Vec<u8>,
    timeout: u32,
    cflag: bool, // connection flag (connection-oriented vs connectionless)
    data: String, // the actual message
    mac: String, // message authentication code
}

impl Packet {
    pub fn new(stream: Vec<u8>) -> Self {
        todo!();
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
