#!/bin/bash -e

rm -f challenge* response* new_challenge* new_response* new_new_challenge_* processed* initial_ceremony* response_list* combined* seed* chunk*

export RUSTFLAGS="-C target-feature=+bmi2,+adx"
CARGO_VER=""
PROVING_SYSTEM=groth16
POWER=18
BATCH=131072
CHUNK_SIZE=131072
CURVE="bw6"
SEED1=$(tr -dc 'A-F0-9' < /dev/urandom | head -c32)
echo $SEED1 > seed1
SEED2=$(tr -dc 'A-F0-9' < /dev/urandom | head -c32)
echo $SEED2 > seed2

function check_hash() {
  test "`xxd -p -c 64 $1.hash`" = "`b2sum $1 | awk '{print $1}'`"
}

cargo $CARGO_VER build --release --bin phase2

phase2_chunked="../../target/release/phase2 --curve-kind $CURVE --chunk-size $CHUNK_SIZE --batch-size $BATCH --contribution-mode full --proving-system $PROVING_SYSTEM"
phase2_1="../../target/release/phase2 --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --seed seed1 --proving-system $PROVING_SYSTEM"
phase2_2="../../target/release/phase2 --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --seed seed2 --proving-system $PROVING_SYSTEM"
####### Phase 2

MAX_CHUNK_INDEX=1

$phase2_chunked new --challenge-fname challenge --challenge-hash-fname challenge.verified.hash --phase1-fname ../../phase1-tests/phase1 --phase1-powers $POWER --num-validators 1 --num-epochs 1
for i in $(seq 0 $(($MAX_CHUNK_INDEX/2))); do
  echo "Contributing and verifying chunk $i..."
  $phase2_1 --chunk-index $i contribute --challenge-fname challenge.$i --challenge-hash-fname challenge.$i.hash --response-fname response_$i --response-hash-fname response_$i.hash
  check_hash challenge.$i
  check_hash response_$i
  $phase2_1 --chunk-index $i verify --challenge-fname challenge.$i --challenge-hash-fname challenge_$i.verified.hash --response-fname response_$i --response-hash-fname response_$i.verified.hash
  rm response_$i.hash
  $phase2_2 --chunk-index $i contribute --challenge-fname response_$i --challenge-hash-fname response_$i.hash --response-fname new_response_$i --response-hash-fname new_response_$i.hash
  check_hash new_response_$i
  $phase2_2 --chunk-index $i verify --challenge-fname response_$i  --challenge-hash-fname response_$i.verified.hash --response-fname new_response_$i --response-hash-fname new_response_$i.verified.hash
  rm challenge.$i response_$i # no longer needed
  echo new_response_$i >> response_list
done

for i in $(seq $(($MAX_CHUNK_INDEX/2 + 1)) $MAX_CHUNK_INDEX); do
  echo "Contributing and verifying chunk $i..."
  $phase2_2 --chunk-index $i contribute --challenge-fname challenge.$i --challenge-hash-fname challenge.$i.hash --response-fname response_$i --response-hash-fname response_$i.hash
  check_hash challenge.$i
  check_hash response_$i
  $phase2_2 --chunk-index $i verify --challenge-fname challenge.$i --challenge-hash-fname challenge_$i.verified.hash --response-fname response_$i --response-hash-fname response_$i.verified.hash
  rm response_$i.hash
  $phase2_1 --chunk-index $i contribute --challenge-fname response_$i --challenge-hash-fname response_$i.hash --response-fname new_response_$i --response-hash-fname new_response_$i.hash
  check_hash new_response_$i
  $phase2_1 --chunk-index $i verify --challenge-fname response_$i  --challenge-hash-fname response_$i.verified.hash --response-fname new_response_$i --response-hash-fname new_response_$i.verified.hash
  rm challenge.$i response_$i # no longer needed
  echo new_response_$i >> response_list
done

$phase2_chunked combine --response-list-fname response_list --initial-query-fname challenge.query --initial-full-fname challenge.full --combined-fname combined

echo "Done!"