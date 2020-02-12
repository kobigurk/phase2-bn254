#!/bin/sh

set -e

if [ ! -f ../powersoftau/phase1radix2m0 ]; then
    echo "Please run powers of tau test first to generate radix files"
    exit 1
fi

# move results of powers of tau here
cp ../powersoftau/phase1radix* .

# compile circuit
npx circom circuit.circom -o circuit.json && npx snarkjs info -c circuit.json
# npx snarkjs info -c circuit.json

# initialize ceremony
cargo run --release --bin new circuit.json circom1.params

cargo run --release --bin contribute circom1.params circom2.params asdajdzixcjlzxjczxlkcjzxlkcj
cargo run --release --bin verify_contribution circuit.json circom1.params circom2.params

cargo run --release --bin contribute circom2.params circom3.params dsfjkshdfakjhsdf
cargo run --release --bin verify_contribution circuit.json circom2.params circom3.params

cargo run --release --bin contribute circom3.params circom4.params askldfjklasdf
cargo run --release --bin verify_contribution circuit.json circom3.params circom4.params

# create dummy keys in circom format
echo "Generating dummy key files..."
npx snarkjs setup --protocol groth
# generate resulting keys
cargo run --release --bin export_keys circom4.params vk.json pk.json
# patch dummy keys with actual keys params
cargo run --release --bin copy_json proving_key.json pk.json transformed_pk.json

# generate solidity verifier
cargo run --release --bin generate_verifier circom4.params verifier.sol

# try to generate and verify proof
npx snarkjs calculatewitness
cargo run --release --bin prove circuit.json witness.json circom4.params proof.json public.json
npx snarkjs verify --vk vk.json --proof proof.json