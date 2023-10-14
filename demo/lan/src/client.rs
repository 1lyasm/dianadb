use std::io::Write;

fn main() {
    println!("Hello, world!");
    let mut stream = std::net::TcpStream::connect("172.31.28.159:6789".to_owned()).unwrap();
    stream.write_all("hi".as_bytes()).unwrap();
}

