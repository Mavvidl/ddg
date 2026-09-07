.PHONY: build test clean

build:
	./scripts/build.sh

test:
	go test ./...
	cargo test --manifest-path rust/ddg-agent/Cargo.toml

clean:
	rm -rf dist rust/ddg-agent/target
