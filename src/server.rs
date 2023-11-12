use dianadb::function;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).unwrap();
    dianadb::Server::run(addr).expect(&format!("{}: run failed", function!()));
}

