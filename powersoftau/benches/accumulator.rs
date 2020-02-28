use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use powersoftau::{
    batched_accumulator::BatchedAccumulator as RawAccumulator, keypair::*, parameters::*,
};
use rand::thread_rng;
use snark_utils::*;
use zexe_algebra::Bls12_377;

use powersoftau_v1::{
    batched_accumulator::BatchedAccumulator,
    keypair::{PrivateKey as PrivateKeyV1, PublicKey as PublicKeyV1},
    parameters::{
        CeremonyParams as CeremonyParamsV1, CheckForCorrectness as CheckForCorrectnessV1,
    },
};

mod utils;
use utils::{compat, generate_input, setup_verify};

// Benchmark comparing the generation of the iterator in parallel chunks
// Parallel generation is strictly better
fn generate_initial_benchmark(c: &mut Criterion) {
    let batch = 256;
    let mut group = c.benchmark_group(format!("generate_initial_{}", batch));
    for compression in &[UseCompression::Yes, UseCompression::No] {
        for power in 2..14 {
            // large powers take too long
            if power > 8 {
                group.sample_size(10);
            }
            let parameters = CeremonyParams::<Bls12_377>::new(power, batch);
            let parameters_v1 = CeremonyParamsV1::<Bls12_377>::new(power, batch);

            let expected_challenge_length = parameters.get_length(*compression);

            // count in `other` powers (G1 will be 2x that)
            group.throughput(Throughput::Elements(power as u64));

            group.bench_with_input(format!("Serial_{}", compression), &power, |b, _power| {
                let mut output = vec![0; expected_challenge_length];
                b.iter(|| {
                    BatchedAccumulator::generate_initial(
                        &mut output,
                        compat(*compression),
                        &parameters_v1,
                    )
                })
            });
            group.bench_with_input(format!("Parallel_{}", compression), &power, |b, _power| {
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
            format!("Serial_{}_{}", in_compressed, out_compressed),
            &size,
            |b, size| {
                let batch = if (batch as u32) >= 2 * 2u32.pow(*size as u32) {
                    2u32.pow(*size as u32) as usize
                } else {
                    batch
                };
                let parameters = CeremonyParamsV1::<Bls12_377>::new(*size, batch);
                let privkey = PrivateKeyV1 {
                    tau: privkey.tau,
                    alpha: privkey.alpha,
                    beta: privkey.beta,
                };
                b.iter(|| {
                    BatchedAccumulator::contribute(
                        &input,
                        &mut output,
                        compat(in_compressed),
                        compat(out_compressed),
                        CheckForCorrectnessV1::Yes,
                        &privkey,
                        &parameters,
                    )
                    .unwrap()
                })
            },
        );

        group.bench_with_input(
            format!("Parallel_{}_{}", in_compressed, out_compressed),
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
    let correctness_v1 = CheckForCorrectnessV1::No;

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
                format!("serial_{}_{}", compressed_input, compressed_output),
                &power,
                |b, power| {
                    let parameters_v1 = CeremonyParamsV1::<Bls12_377>::new(*power, batch);
                    let pubkey_v1 = PublicKeyV1 {
                        tau_g1: pubkey.tau_g1,
                        alpha_g1: pubkey.alpha_g1,
                        beta_g1: pubkey.beta_g1,
                        tau_g2: pubkey.tau_g2,
                        alpha_g2: pubkey.alpha_g2,
                        beta_g2: pubkey.beta_g2,
                    };
                    b.iter(|| {
                        BatchedAccumulator::verify_transformation(
                            &input,
                            &output,
                            &pubkey_v1,
                            &current_accumulator_hash,
                            compat(*compressed_input),
                            compat(*compressed_output),
                            correctness_v1,
                            correctness_v1,
                            &parameters_v1,
                        )
                        .unwrap()
                    })
                },
            );

            group.bench_with_input(
                format!("parallel_{}_{}", compressed_input, compressed_output),
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
