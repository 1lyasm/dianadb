use std::io::{Write, Read};

fn handle_client(stream: &mut std::net::TcpStream) {
    let mut request = String::new();
    stream.read_to_string(&mut request).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
}

fn main() {
    let listener = std::net::TcpListener::bind("0.0.0.0:6789").unwrap();
    for stream in listener.incoming() {
        handle_client(&mut stream.unwrap());
    }
    println!("this is server");
}

