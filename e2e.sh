#!/bin/bash

rm -f challenge* response* new_challenge* processed*

# 3 validators and 3 epochs keep us just below 512k constraints (2^19)
POWER=25
NUM_VALIDATORS=100
NUM_EPOCHS=30
BATCH=1000000
CURVE="sw6"

powersoftau="cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $POWER"
phase2="cargo run --release --bin prepare_phase2 -- --curve-kind $CURVE --batch-size $BATCH --power $POWER --phase2-size $POWER"
snark="cargo run --release --bin bls-snark-setup --"

####### Phase 1

$powersoftau new --challenge-fname challenge
yes | $powersoftau contribute --challenge-fname challenge --response-fname response
rm challenge # no longer needed

###### Prepare Phase 2

$phase2 --response-fname response --phase2-fname processed --phase2-size $POWER

###### Phase 2

$snark new --phase1 processed --output ceremony --num-epochs $NUM_EPOCHS --num-validators $NUM_VALIDATORS
cp ceremony initial
$snark contribute --data ceremony
$snark contribute --data ceremony

$snark verify --before initial --after ceremony

# done! since `verify` passed, you can be sure that this will work
# as shown in the `mpc.rs` example
