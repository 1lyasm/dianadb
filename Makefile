build:
	RUST_LOG=trace cargo build
run:
	RUST_LOG=trace cargo run
test:
	RUST_LOG=trace cargo test -- --nocapture
