# Use ubuntu 20.04 for building, otherwise the binary will not work on gramine image

cd ./powersoftau
cargo build --release --bin new_constrained
cargo build --release --bin compute_constrained
cargo build --release --bin verify_transform_constrained
cargo build --release --bin beacon_constrained
cargo build --release --bin prepare_phase2

mkdir -p ../dist/bin
cp target/release/new_constrained ../dist/bin
cp target/release/compute_constrained ../dist/bin
cp target/release/verify_transform_constrained ../dist/bin
cp target/release/beacon_constrained ../dist/bin
cp target/release/prepare_phase2 ../dist/bin

cd ../phase2

cargo build --release --bin new
cargo build --release --bin contribute
cargo build --release --bin verify_contribution

cp target/release/new ../dist/bin
cp target/release/contribute ../dist/bin
cp target/release/verify_contribution ../dist/bin
