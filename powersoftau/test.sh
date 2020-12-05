#!/bin/sh

rm challenge*
rm response*
rm transcript
rm phase1radix*
rm tmp_*

set -e

SIZE=15
BATCH=256

cargo run --release --bin new_constrained challenge1 $SIZE $BATCH
yes | cargo run --release --bin compute_constrained challenge1 response1 $SIZE $BATCH
cargo run --release --bin verify_transform_constrained challenge1 response1 challenge2 $SIZE $BATCH

yes | cargo run --release --bin compute_constrained challenge2 response2 $SIZE $BATCH
cargo run --release --bin verify_transform_constrained challenge2 response2 challenge3 $SIZE $BATCH

yes | cargo run --release --bin compute_constrained challenge3 response3 $SIZE $BATCH
cargo run --release --bin verify_transform_constrained challenge3 response3 challenge4 $SIZE $BATCH

cargo run --release --bin beacon_constrained challenge4 response4 $SIZE $BATCH 0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620 10
cargo run --release --bin verify_transform_constrained challenge4 response4 challenge5 $SIZE $BATCH

cargo run --release --bin prepare_phase2 response4 $SIZE $BATCH
