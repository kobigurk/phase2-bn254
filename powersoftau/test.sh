#!/bin/sh

rm challenge*
rm response*
rm transcript
rm phase1radix*
rm tmp_*

set -e

cargo run --release --features smalltest --bin new_constrained challenge1
yes | cargo run --release --features smalltest --bin compute_constrained challenge1 response1
cargo run --release --features smalltest --bin verify_transform_constrained challenge1 response1 challenge2

yes | cargo run --release --features smalltest --bin compute_constrained challenge2 response2
cargo run --release --features smalltest --bin verify_transform_constrained challenge2 response2 challenge3

yes | cargo run --release --features smalltest --bin compute_constrained challenge3 response3
cargo run --release --features smalltest --bin verify_transform_constrained challenge3 response3 challenge4

cargo run --release --features smalltest --bin beacon_constrained challenge4 response4
cargo run --release --features smalltest --bin verify_transform_constrained challenge4 response4 challenge5

cat response1 response2 response3 response4 > transcript
cargo run --release --features smalltest --bin verify  transcript
