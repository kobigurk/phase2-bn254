#!/bin/sh

rm -f pk.json vk.json transformed_vk.json transformed_pk.* proof.json

set -e

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

# generate resulting keys
cargo run --release --bin export_keys circom4.params vk.json pk.json

# create dummy keys in circom format
npx snarkjs setup --protocol groth
# patch dummy keys with actual keys params
node patch_vk.js
# generate binary version of proving key
node node_modules/websnark/tools/buildpkey.js -i transformed_pk.json -o transformed_pk.bin

# try to generate and verify proof
snarkjs calculatewitness
node node_modules/websnark/tools/buildwitness.js -i witness.json -o witness.bin
snarkjs proof # to get public inputs json only
./cli.js
snarkjs verify --vk transformed_vk.json --proof proof.json