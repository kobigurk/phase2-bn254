#!/bin/bash

rm -f challenge* response* new_challenge* new_response* new_new_challenge_* processed* initial_ceremony* response_list* combined* seed* chunk*

PROVING_SYSTEM=$1
POWER=10
BATCH=64
CHUNK_SIZE=512
if [ "$PROVING_SYSTEM" == "groth16" ]; then
  MAX_CHUNK_INDEX=3 # we have 4 chunks, since we have a total of 2^11-1 powers
else
  MAX_CHUNK_INDEX=1 # we have 2 chunks, since we have a total of 2^11-1 powers
fi
CURVE="bw6"
SEED1=$(tr -dc 'A-F0-9' < /dev/urandom | head -c32)
echo $SEED1 > seed1
SEED2=$(tr -dc 'A-F0-9' < /dev/urandom | head -c32)
echo $SEED2 > seed2

phase1_1="cargo run --release --bin phase1 -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --seed seed1 --proving-system $PROVING_SYSTEM"
phase1_2="cargo run --release --bin phase1 -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --seed seed2 --proving-system $PROVING_SYSTEM"
phase1_combine="cargo run --release --bin phase1 -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --proving-system $PROVING_SYSTEM"
phase1_full="cargo run --release --bin phase1 -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode full --power $POWER --proving-system $PROVING_SYSTEM"

####### Phase 1

for i in $(seq 0 $(($MAX_CHUNK_INDEX/2))); do
  $phase1_1 --chunk-index $i new --challenge-fname challenge_$i
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname challenge_$i --response-fname response_$i
  $phase1_1 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname challenge_$i --response-fname response_$i --new-challenge-fname new_challenge_$i
  yes | $phase1_2 --chunk-index $i contribute --challenge-fname new_challenge_$i --response-fname new_response_$i
  $phase1_2 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname new_challenge_$i --response-fname new_response_$i --new-challenge-fname new_new_challenge_$i
  rm challenge_$i new_challenge_$i new_new_challenge_$i # no longer needed
  echo new_response_$i >> response_list
done

for i in $(seq $(($MAX_CHUNK_INDEX/2 + 1)) $MAX_CHUNK_INDEX); do
  $phase1_1 --chunk-index $i new --challenge-fname challenge_$i
  yes | $phase1_2 --chunk-index $i contribute --challenge-fname challenge_$i --response-fname response_$i
  $phase1_1 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname challenge_$i --response-fname response_$i --new-challenge-fname new_challenge_$i
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname new_challenge_$i --response-fname new_response_$i
  $phase1_2 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname new_challenge_$i --response-fname new_response_$i --new-challenge-fname new_new_challenge_$i
  rm challenge_$i new_challenge_$i new_new_challenge_$i # no longer needed
  echo new_response_$i >> response_list
done

$phase1_combine combine --response-list-fname response_list --combined-fname combined
$phase1_full beacon --challenge-fname combined --response-fname response_beacon --beacon-hash 0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620
$phase1_full verify-and-transform-pok-and-correctness --challenge-fname combined --response-fname response_beacon --new-challenge-fname response_beacon_new_challenge
$phase1_full verify-and-transform-ratios --response-fname response_beacon_new_challenge

$phase1_combine split --chunk-fname-prefix chunk_split --full-fname response_beacon

for i in $(seq 0 $(($MAX_CHUNK_INDEX/2))); do
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname chunk_split_$i --response-fname response_split_$i
  $phase1_1 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname chunk_split_$i --response-fname response_split_$i --new-challenge-fname new_challenge_split_$i
  yes | $phase1_2 --chunk-index $i contribute --challenge-fname new_challenge_split_$i --response-fname new_response_split_$i
  $phase1_2 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname new_challenge_split_$i --response-fname new_response_split_$i --new-challenge-fname new_new_challenge_split_$i
  rm chunk_split_$i new_challenge_split_$i new_new_challenge_split_$i # no longer needed
  echo new_response_split_$i >> response_list_split
done

for i in $(seq $(($MAX_CHUNK_INDEX/2 + 1)) $MAX_CHUNK_INDEX); do
  yes | $phase1_2 --chunk-index $i contribute --challenge-fname chunk_split_$i --response-fname response_split_$i
  $phase1_2 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname chunk_split_$i --response-fname response_split_$i --new-challenge-fname new_challenge_split_$i
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname new_challenge_split_$i --response-fname new_response_split_$i
  $phase1_1 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname new_challenge_split_$i --response-fname new_response_split_$i --new-challenge-fname new_new_challenge_split_$i
  rm chunk_split_$i new_challenge_split_$i new_new_challenge_split_$i # no longer needed
  echo new_response_split_$i >> response_list_split
done

$phase1_combine combine --response-list-fname response_list_split --combined-fname combined_split
$phase1_full beacon --challenge-fname combined_split --response-fname response_beacon_split --beacon-hash 0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620
$phase1_full verify-and-transform-pok-and-correctness --challenge-fname combined_split --response-fname response_beacon_split --new-challenge-fname response_beacon_new_challenge_split
$phase1_full verify-and-transform-ratios --response-fname response_beacon_new_challenge_split
