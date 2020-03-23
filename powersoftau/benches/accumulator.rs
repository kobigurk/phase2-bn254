use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use powersoftau::{keypair::*, parameters::*, BatchedAccumulator as RawAccumulator};
use rand::thread_rng;
use snark_utils::*;
use zexe_algebra::Bls12_377;

use test_helpers::{generate_input, setup_verify};

// Benchmark comparing the generation of the iterator in parallel chunks
// Parallel generation is strictly better
fn generate_initial_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_initial");
    for compression in &[UseCompression::Yes, UseCompression::No] {
        for power in 10..14 {
            // large powers take too long
            if power > 8 {
                group.sample_size(10);
            }
            let parameters = CeremonyParams::<Bls12_377>::new(power, power);
            let expected_challenge_length = parameters.get_length(*compression);

            // count in `other` powers (G1 will be 2x that)
            group.throughput(Throughput::Elements(power as u64));
            group.bench_with_input(format!("{}", compression), &power, |b, _power| {
                let mut output = vec![0; expected_challenge_length];
                b.iter(|| RawAccumulator::generate_initial(&mut output, *compression, &parameters))
            });
        }
    }
}

// Benchmark comparing contributing to the ceremony
fn contribute_benchmark(c: &mut Criterion) {
    let batch = 256;
    let mut group = c.benchmark_group(format!("contribute_{}", batch));
    group.sample_size(10);
    let in_compressed = UseCompression::No;
    let out_compressed = UseCompression::Yes;

    // we gather data on various sizes
    for size in 4..8 {
        let parameters = CeremonyParams::<Bls12_377>::new(size, batch);
        let (input, _) = generate_input(&parameters, in_compressed);
        let mut output = vec![0; parameters.get_length(out_compressed)];
        let current_accumulator_hash = blank_hash();
        let mut rng = thread_rng();
        // generate the private key
        let (_, privkey) = keypair(&mut rng, current_accumulator_hash.as_ref())
            .expect("could not generate keypair");

        group.bench_with_input(
            format!("{}_{}", in_compressed, out_compressed),
            &size,
            |b, _size| {
                b.iter(|| {
                    RawAccumulator::contribute(
                        &input,
                        &mut output,
                        in_compressed,
                        out_compressed,
                        CheckForCorrectness::Yes,
                        &privkey,
                        &parameters,
                    )
                    .unwrap()
                })
            },
        );
    }
}

// Benchmark comparing contributing to the ceremony for various sizes and input/output
// compressed situations. Parallel verification is consistently faster by 10-15% in all
// modes of operation
fn verify_benchmark(c: &mut Criterion) {
    let correctness = CheckForCorrectness::No;

    // Iterate over all combinations of the following parameters
    let compression = &[
        (UseCompression::Yes, UseCompression::Yes),
        (UseCompression::No, UseCompression::Yes),
        (UseCompression::Yes, UseCompression::No),
        (UseCompression::No, UseCompression::No),
    ];
    let powers = (4..12).map(|i| 2u32.pow(i) as usize);
    let batch = 256;

    let mut group = c.benchmark_group(format!("verify_{}", batch));
    group.sample_size(10); // these would take way too long otherwise

    // Test the benchmark for everything in the parameter space
    for power in powers {
        for (compressed_input, compressed_output) in compression {
            let parameters = CeremonyParams::<Bls12_377>::new(power, batch);

            let (input, output, pubkey, current_accumulator_hash) =
                setup_verify(*compressed_input, *compressed_output, &parameters);

            group.bench_with_input(
                format!("{}_{}", compressed_input, compressed_output),
                &power,
                |b, _power| {
                    b.iter(|| {
                        RawAccumulator::verify_transformation(
                            &input,
                            &output,
                            &pubkey,
                            &current_accumulator_hash,
                            *compressed_input,
                            *compressed_output,
                            correctness,
                            correctness,
                            &parameters,
                        )
                        .unwrap()
                    })
                },
            );
        }
    }
}

criterion_group!(
    benches,
    generate_initial_benchmark,
    contribute_benchmark,
    verify_benchmark
);
criterion_main!(benches);
