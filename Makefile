.PHONY: fmt check test bpf-configure ui-install

fmt:
	cargo fmt --all

check:
	cargo check --workspace

test:
	cargo test --workspace

bpf-configure:
	cmake -S . -B build

ui-install:
	npm --prefix ui install
