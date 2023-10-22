all:
	cargo build
test:
	RUST_LOG=trace cargo test -- --nocapture
