#!/bin/bash

rm -f challenge* response* new_challenge* processed* initial_ceremony* response_list* combined* seed*

POWER=10
BATCH=64
MAX_CHUNK_INDEX=3 # we have 16 chunks, since we have a total of 2^11-1 powers
CURVE="bw6"
SEED=`tr -dc 'A-F0-9' < /dev/urandom | head -c32`
echo $SEED > seed1

powersoftau="cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode full --power $POWER --seed seed1"

####### Phase 1

$powersoftau new --challenge-fname challenge
yes | $powersoftau contribute --challenge-fname challenge --response-fname response
$powersoftau verify-and-transform-pok-and-correctness --challenge-fname challenge --response-fname response --new-challenge-fname new_challenge
$powersoftau beacon --challenge-fname new_challenge --response-fname new_response --beacon-hash 0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620
$powersoftau verify-and-transform-pok-and-correctness --challenge-fname new_challenge --response-fname new_response --new-challenge-fname new_challenge_2
$powersoftau verify-and-transform-ratios --response-fname new_challenge_2

