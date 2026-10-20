#!/usr/bin/env bash
cd "$(dirname "$0")" || exit 1

if [ -f "./target/release/nexshield-cli" ]; then
    ./target/release/nexshield-cli run "$@"
else
    cargo run --release -p nexshield-cli -- run "$@"
fi
