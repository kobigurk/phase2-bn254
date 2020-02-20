use criterion::{criterion_group, criterion_main, Criterion};

use powersoftau::utils::generate_powers_of_tau;

use std::ops::MulAssign;
use zexe_algebra::{curves::bls12_377::Bls12_377, Field, PairingEngine, UniformRand, Zero};

// This was the previous implementation using chunks, we keep it here to compare performance
// against the Rayon implementation
pub fn generate_powers_of_tau_crossbeam<E: PairingEngine>(
    tau: &E::Fr,
    start: usize,
    size: usize,
) -> Vec<E::Fr> {
    // Construct the powers of tau
    let mut taupowers = vec![E::Fr::zero(); size];
    let chunk_size = size / num_cpus::get();

    // Construct exponents in parallel chunks
    crossbeam::scope(|scope| {
        for (i, taupowers) in taupowers.chunks_mut(chunk_size).enumerate() {
            scope.spawn(move || {
                let mut acc = tau.pow(&[(start + i * chunk_size) as u64]);

                for t in taupowers {
                    *t = acc;
                    acc.mul_assign(&tau);
                }
            });
        }
    });
    taupowers
}

// Benchmark showing that the Rayon generator is faster
fn powersoftau_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let start = 0;
    let end = 50;
    let point = <Bls12_377 as PairingEngine>::Fr::rand(&mut rng);

    let mut group = c.benchmark_group("PowersOfTau");
    group.bench_function("rayon", |b| {
        b.iter(|| generate_powers_of_tau::<Bls12_377>(&point, start, end))
    });
    group.bench_function("crossbeam", |b| {
        b.iter(|| generate_powers_of_tau_crossbeam::<Bls12_377>(&point, start, end))
    });
    group.finish();
}

criterion_group!(benches, powersoftau_benchmark);
criterion_main!(benches);
