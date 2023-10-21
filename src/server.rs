use dianadb::function;

fn main() {
    dianadb::Server::run().expect(&format!("{}: run failed", function!()));
}

