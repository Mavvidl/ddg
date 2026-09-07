#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p dist
cargo build --release --manifest-path rust/ddg-agent/Cargo.toml
cp rust/ddg-agent/target/release/ddg-agent dist/ddg-agent
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/ddg ./cmd/ddg
printf 'Built dist/ddg and dist/ddg-agent\n'
