#!/bin/sh

rm challenge*
rm response*
rm transcript
rm phase1radix*
rm tmp_*

set -e

SIZE=8
BATCH=256
CURVE="bls12_381"

cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $SIZE new --challenge-fname challenge1
yes | cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $SIZE contribute --challenge-fname challenge1 --response-fname response1
cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $SIZE verify-and-transform --challenge-fname challenge1 --response-fname response1 --new-challenge-fname challenge2

yes | cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $SIZE contribute --challenge-fname challenge2 --response-fname response2
cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $SIZE verify-and-transform --challenge-fname challenge2 --response-fname response2 --new-challenge-fname challenge3

yes | cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $SIZE contribute --challenge-fname challenge3 --response-fname response3
cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $SIZE verify-and-transform --challenge-fname challenge3 --response-fname response3 --new-challenge-fname challenge4

# add a randomness contribution by a beacon at the end
cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $SIZE beacon --challenge-fname challenge4 --response-fname response4
cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $SIZE verify-and-transform --challenge-fname challenge4 --response-fname response4 --new-challenge-fname challenge5