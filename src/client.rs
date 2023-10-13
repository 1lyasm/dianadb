use std::io::Write;

#[macro_use]
extern crate log;

#[macro_use]
mod util;

#[derive(serde::Serialize, serde::Deserialize)]
struct Config {
    shard_count: usize,
    addresses: Vec<String>,
    pools: Vec<usize>,
}

impl Config {
    fn init_shard_count(&mut self) {
        self.shard_count = std::env::args()
            .nth(1)
            .expect(&format!("{}: shard_count is missing", function!()))
            .parse()
            .expect(&format!("{}: invalid shard_count", function!()));
    }

    fn validate(&self) {
        let mut is_valid = true;
        let server_count = self.addresses.len();
        let replica_count = server_count / self.shard_count;
        if server_count % self.shard_count != 0 {
            is_valid = false;
        }
        if replica_count <= 1 || replica_count % 2 == 0 {
            is_valid = false;
        }
        if !is_valid {
            panic!("{}: invalid conf", function!());
        }
    }

    fn init_addresses(&mut self) {
        std::io::stdin()
            .lines()
            .for_each(|line| self.addresses.push(line.unwrap()));
        self.validate();
    }

    fn init_pools(&mut self) {
        let (mut current_pool, mut j) = (0, 0);
        let server_count = self.addresses.len();
        let replica_count = server_count / self.shard_count;
        for i in 0..server_count {
            if j == replica_count {
                current_pool += 1;
                j = 0;
            }
            *self.pools.get_mut(i).unwrap() = current_pool;
            j += 1;
        }
    }

    fn merge_by_pools(&self, pool_addresses: &mut std::vec::Vec<String>) {
        for _ in 0..self.shard_count {
            pool_addresses.push("".to_owned());
        }
        for i in 0..self.addresses.len() {
            pool_addresses
                .get_mut(*self.pools.get(i).unwrap())
                .unwrap()
                .push_str(&(self.addresses.get(i).unwrap().to_owned()));
        }
    }

    fn send(&self) {
        let mut pool_addresses = std::vec::Vec::new();
        self.merge_by_pools(&mut pool_addresses);
        for i in 0..self.addresses.len() {
            let address = self.addresses.get(i).unwrap();
            let pool = self.pools.get(i).unwrap();
            let connection_result = std::net::TcpStream::connect(address.to_owned());
            if connection_result.is_err() {
                panic!("{}: connect failed {}", function!(), address.to_owned());
            }
            let mut stream = connection_result.unwrap();
            let write_result = stream.write(&self.shard_count.to_ne_bytes());
            if write_result.is_err() {
                panic!("{}: write failed", function!());
            }
            if stream
                .write_all(pool_addresses.get(*pool).unwrap().as_bytes())
                .is_err()
            {
                panic!("{}: write_all failed", function!());
            }
        }
    }

    fn init(&mut self) {
        self.init_shard_count();
        self.init_addresses();
        self.init_pools();
        info!(
            "{}: conf: \n{}",
            function!(),
            serde_json::to_string_pretty(&self).unwrap()
        );
    }
}

fn main() {
    env_logger::init();
    let mut conf = Config {
        shard_count: 0,
        addresses: Vec::new(),
        pools: Vec::new(),
    };
    conf.init();
    conf.send();
}