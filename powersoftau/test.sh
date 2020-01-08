#!/bin/sh

rm challenge*
rm response*
rm transcript
rm phase1radix*
rm tmp_*

set -e

cargo run --release --bin new_constrained challenge1
cargo run --release --bin compute_constrained challenge1 response1
cargo run --release --bin verify_transform_constrained challenge1 response1 challenge2

cargo run --release --bin beacon_constrained challenge2 response2
cargo run --release --bin verify_transform_constrained challenge2 response2 challenge3

cargo run --release --bin beacon_constrained challenge3 response3
cargo run --release --bin verify_transform_constrained challenge3 response3 challenge4

cargo run --release --bin beacon_constrained challenge4 response4
cargo run --release --bin verify_transform_constrained challenge4 response4 challenge5

cat response1 response2 response3 response4 > transcript
cargo run --release --bin verify transcript