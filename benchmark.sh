#!/bin/bash

rm -f challenge* response* new_challenge* processed* initial_ceremony* response_list* combined*

POWER=27
BATCH=2097152
CURVE="bw6"
SEED=`tr -dc 'A-F0-9' < /dev/urandom | head -c32`

powersoftau="cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $POWER --seed $SEED"
phase2="cargo run --release --bin prepare_phase2 -- --curve-kind $CURVE --batch-size $BATCH --power $POWER --phase2-size $POWER"
snark="cargo run --release --bin bls-snark-setup --"

$powersoftau --chunk-index 0 new --challenge-fname challenge_0
time yes | $powersoftau --chunk-index 0 contribute --challenge-fname challenge_0 --response-fname response_0

rm -f challenge* response* new_challenge* processed* initial_ceremony* response_list* combined*
