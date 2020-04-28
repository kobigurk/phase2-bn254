#!/bin/sh

set -e

if [ ! -f ../powersoftau/phase1radix2m0 ]; then
    echo "Please run powers of tau test first to generate radix files"
    exit 1
fi

# move results of powers of tau here
cp ../powersoftau/phase1radix* .

# npm install

# compile circuit
npx circom circuit.circom -o circuit.json && npx snarkjs info -c circuit.json
# npx snarkjs info -c circuit.json

# initialize ceremony
cargo run --release --bin new circuit.json circom1.params ./

cargo run --release --bin contribute circom1.params circom2.params asdajdzixcjlzxjczxlkcjzxlkcj
cargo run --release --bin verify_contribution circuit.json circom1.params circom2.params ./

cargo run --release --bin contribute circom2.params circom3.params dsfjkshdfakjhsdf
cargo run --release --bin verify_contribution circuit.json circom2.params circom3.params ./

cargo run --release --bin contribute circom3.params circom4.params askldfjklasdf
cargo run --release --bin verify_contribution circuit.json circom3.params circom4.params ./

cp circom4.params params.bin

# For info how to use and export resulting params see readme from zkutil crate:
# https://github.com/poma/zkutil

cargo install --root . zkutil

# Export keys to snarkjs/websnark compatible format
./bin/zkutil export-keys

# Generate a solidity verifier contract
./bin/zkutil generate-verifier

### Generating and verifying test proof ###

# Make sure you have a correct input.json file in order for that to work
snarkjs calculatewitness
./bin/zkutil prove
./bin/zkutil verify
snarkjs verify
