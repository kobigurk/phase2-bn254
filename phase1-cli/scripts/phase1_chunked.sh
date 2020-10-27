#!/bin/bash -e

rm -f challenge* response* new_challenge* new_response* new_new_challenge_* processed* initial_ceremony* response_list* combined* seed* chunk*

export RUSTFLAGS="-C target-feature=+bmi2,+adx"
CARGO_VER=""
PROVING_SYSTEM=$1
POWER=10
BATCH=64
CHUNK_SIZE=512
if [ "$PROVING_SYSTEM" == "groth16" ]; then
  MAX_CHUNK_INDEX=$((4-1)) # we have 4 chunks, since we have a total of 2^11-1 powers
else
  MAX_CHUNK_INDEX=$((2-1)) # we have 2 chunks, since we have a total of 2^11-1 powers
fi
CURVE="bw6"
SEED1=$(tr -dc 'A-F0-9' < /dev/urandom | head -c32)
echo $SEED1 > seed1
SEED2=$(tr -dc 'A-F0-9' < /dev/urandom | head -c32)
echo $SEED2 > seed2

function check_hash() {
  test "`xxd -p -c 64 $1.hash`" = "`b2sum $1 | awk '{print $1}'`"
}

cargo $CARGO_VER build --release --bin phase1

phase1_1="../../target/release/phase1 --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --seed seed1 --proving-system $PROVING_SYSTEM"
phase1_2="../../target/release/phase1 --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --seed seed2 --proving-system $PROVING_SYSTEM"
phase1_combine="../../target/release/phase1 --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --proving-system $PROVING_SYSTEM"
phase1_full="../../target/release/phase1 --curve-kind $CURVE --batch-size $BATCH --contribution-mode full --power $POWER --proving-system $PROVING_SYSTEM"
####### Phase 1

for i in $(seq 0 $(($MAX_CHUNK_INDEX/2))); do
  echo "Contributing and verifying chunk $i..."
  $phase1_1 --chunk-index $i new --challenge-fname challenge_$i --challenge-hash-fname challenge_$i.verified.hash
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname challenge_$i --challenge-hash-fname challenge_$i.hash --response-fname response_$i --response-hash-fname response_$i.hash
  check_hash challenge_$i
  check_hash response_$i
  $phase1_1 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname challenge_$i --challenge-hash-fname challenge_$i.verified.hash --response-fname response_$i --response-hash-fname response_$i.verified.hash --new-challenge-fname new_challenge_$i --new-challenge-hash-fname new_challenge_$i.verified.hash
  yes | $phase1_2 --chunk-index $i contribute --challenge-fname new_challenge_$i --challenge-hash-fname new_challenge_$i.hash --response-fname new_response_$i --response-hash-fname new_response_$i.hash
  check_hash new_challenge_$i
  check_hash new_response_$i
  $phase1_2 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname new_challenge_$i  --challenge-hash-fname new_challenge_$i.verified.hash --response-fname new_response_$i --new-challenge-fname new_new_challenge_$i --response-hash-fname new_response_$i.verified.hash --new-challenge-hash-fname new_new_challenge_$i.verified.hash
  rm challenge_$i new_challenge_$i new_new_challenge_$i # no longer needed
  echo new_response_$i >> response_list
done

for i in $(seq $(($MAX_CHUNK_INDEX/2 + 1)) $MAX_CHUNK_INDEX); do
  echo "Contributing and verifying chunk $i..."
  $phase1_1 --chunk-index $i new --challenge-fname challenge_$i --challenge-hash-fname challenge_$i.verified.hash
  yes | $phase1_2 --chunk-index $i contribute --challenge-fname challenge_$i --challenge-hash-fname challenge_$i.hash --response-fname response_$i --response-hash-fname response_$i.hash
  check_hash challenge_$i
  check_hash response_$i
  $phase1_1 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname challenge_$i --challenge-hash-fname challenge_$i.verified.hash --response-fname response_$i --response-hash-fname response_$i.verified.hash --new-challenge-fname new_challenge_$i --new-challenge-hash-fname new_challenge_$i.verified.hash
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname new_challenge_$i --challenge-hash-fname new_challenge_$i.hash --response-fname new_response_$i --response-hash-fname new_response_$i.hash
  check_hash new_challenge_$i
  check_hash new_response_$i
  $phase1_2 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname new_challenge_$i  --challenge-hash-fname new_challenge_$i.verified.hash --response-fname new_response_$i --new-challenge-fname new_new_challenge_$i --response-hash-fname new_response_$i.verified.hash --new-challenge-hash-fname new_new_challenge_$i.verified.hash
  rm challenge_$i new_challenge_$i new_new_challenge_$i # no longer needed
  echo new_response_$i >> response_list
done

echo "Aggregating..."
$phase1_combine combine --response-list-fname response_list --combined-fname combined
echo "Apply beacon..."
$phase1_full beacon --challenge-fname combined --response-fname response_beacon --beacon-hash 0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620
echo "Verifying..."
$phase1_full verify-and-transform-pok-and-correctness --challenge-fname combined --challenge-hash-fname combined.verified.hash --response-fname response_beacon --response-hash-fname response_beacon.verified.hash --new-challenge-fname response_beacon_new_challenge --new-challenge-hash-fname response_beacon_new_challenge.verified.hash
$phase1_full verify-and-transform-ratios --response-fname response_beacon_new_challenge

echo "Doing the same for splitting..."
$phase1_combine split --chunk-fname-prefix chunk_split --full-fname response_beacon

for i in $(seq 0 $(($MAX_CHUNK_INDEX/2))); do
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname chunk_split_$i --challenge-hash-fname chunk_split_$i.hash --response-fname response_split_$i --response-hash-fname response_split_$i.hash
  check_hash chunk_split_$i
  check_hash response_split_$i
  $phase1_2 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname chunk_split_$i --challenge-hash-fname chunk_split_$i.verified.hash --response-fname response_split_$i --response-hash-fname response_split_$i.verified.hash --new-challenge-fname new_challenge_split_$i --new-challenge-hash-fname new_challenge_split_$i.verified.hash
  yes | $phase1_2 --chunk-index $i contribute --challenge-fname new_challenge_split_$i --challenge-hash-fname new_challenge_split_$i.hash  --response-fname new_response_split_$i --response-hash-fname new_response_split_$i.hash
  check_hash new_challenge_split_$i
  check_hash new_response_split_$i
  $phase1_1 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname new_challenge_split_$i --challenge-hash-fname new_challenge_split_$i.verified.hash --response-fname new_response_split_$i --response-hash-fname new_response_split_$i.verified.hash --new-challenge-fname new_new_challenge_split_$i --new-challenge-hash-fname new_new_challenge_split_$i.verified.hash
  rm chunk_split_$i new_challenge_split_$i new_new_challenge_split_$i # no longer needed
  echo new_response_split_$i >> response_list_split
done

for i in $(seq $(($MAX_CHUNK_INDEX/2 + 1)) $MAX_CHUNK_INDEX); do
  yes | $phase1_2 --chunk-index $i contribute --challenge-fname chunk_split_$i --challenge-hash-fname chunk_split_$i.hash --response-fname response_split_$i --response-hash-fname response_split_$i.hash
  check_hash chunk_split_$i
  check_hash response_split_$i
  $phase1_2 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname chunk_split_$i --challenge-hash-fname chunk_split_$i.verified.hash --response-fname response_split_$i --response-hash-fname response_split_$i.verified.hash --new-challenge-fname new_challenge_split_$i --new-challenge-hash-fname new_challenge_split_$i.verified.hash
  yes | $phase1_1 --chunk-index $i contribute --challenge-fname new_challenge_split_$i --challenge-hash-fname new_challenge_split_$i.hash --response-fname new_response_split_$i --response-hash-fname new_response_split_$i.hash
  check_hash new_challenge_split_$i
  check_hash new_response_split_$i
  $phase1_1 --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname new_challenge_split_$i --challenge-hash-fname new_challenge_split_$i.verified.hash --response-fname new_response_split_$i --response-hash-fname new_response_split_$i.verified.hash --new-challenge-fname new_new_challenge_split_$i --new-challenge-hash-fname new_new_challenge_split_$i.verified.hash
  rm chunk_split_$i new_challenge_split_$i new_new_challenge_split_$i # no longer needed
  echo new_response_split_$i >> response_list_split
done

$phase1_combine combine --response-list-fname response_list_split --combined-fname combined_split
$phase1_full beacon --challenge-fname combined_split --challenge-hash-fname challenge_$i.hash --response-fname response_beacon_split --response-hash-fname response_$i.hash --beacon-hash 0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620
$phase1_full verify-and-transform-pok-and-correctness --challenge-fname combined_split --challenge-hash-fname combined_split.verified.hash --response-fname response_beacon_split --response-hash-fname response_beacon_split.verified.hash --new-challenge-fname response_beacon_new_challenge_split --new-challenge-hash-fname response_beacon_new_challenge_split.verified.hash
$phase1_full verify-and-transform-ratios --response-fname response_beacon_new_challenge_split
echo "Done!"