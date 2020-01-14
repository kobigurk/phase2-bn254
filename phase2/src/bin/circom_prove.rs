extern crate bellman_ce;
extern crate rand;
extern crate phase2;

// For randomness (during paramgen and proof generation)
use rand::{thread_rng, Rng};
use std::sync::Arc;

// For benchmarking
use std::time::{Duration, Instant};

// Bring in some tools for using pairing-friendly curves
use bellman_ce::pairing::{
    Engine,
    ff::Field,
    CurveAffine,
};

use bellman_ce::pairing::bn256::{
    Bn256,
};

// We'll use these interfaces to construct our circuit.
use bellman_ce::{
    Circuit,
    ConstraintSystem,
    SynthesisError
};

// We're going to use the Groth16 proving system.
use bellman_ce::groth16::{
    Proof,
    prepare_verifying_key,
    create_random_proof,
    verify_proof,
};

use std::fs;
use std::fs::OpenOptions;

use phase2::parameters::MPCParameters;
use phase2::circom_circuit::CircomCircuit;

fn main() {
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut thread_rng();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        println!("Usage: \n<in_params.params> <circuit.json> <witness.json>");
        std::process::exit(exitcode::USAGE);
    }
    let params_filename = &args[1];
    let circuit_filename = &args[2];
    let witness_filename = &args[3];
    let reader = OpenOptions::new()
                            .read(true)
                            .open(params_filename)
                            .expect("unable to open.");
    let mut params = MPCParameters::read(reader, false, true).expect("unable to read params");

    let params = params.get_params_mut();
    params.vk.ic = params.vk.ic.clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>();
    params.h = Arc::new((*params.h).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());
    params.a = Arc::new((*params.a).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());
    params.b_g1 = Arc::new((*params.b_g1).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());
    params.b_g2 = Arc::new((*params.b_g2).clone().into_iter().filter(|x| !x.is_zero()).collect::<Vec<_>>());

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    // Let's benchmark stuff!
    const SAMPLES: u32 = 1;
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    // Just a place to put the proof data, so we can
    // benchmark deserialization.
    let mut proof_vec = vec![];

    for _ in 0..SAMPLES {
        proof_vec.truncate(0);

        let start = Instant::now();
        let mut witness = vec![];
        {
            // Create an instance of our circuit (with the
            // witness)
            let c = CircomCircuit {
                file_name: circuit_filename,
                witness_file_name: witness_filename,
                has_witness: true,
            };
            witness = c.parse_witness::<Bn256>().0;

            // Create a groth16 proof with our parameters.
            let proof = create_random_proof(c, &*params, rng).unwrap();

            proof.write(&mut proof_vec).unwrap();
        }

        total_proving += start.elapsed();

        let start = Instant::now();
        let proof = Proof::read(&proof_vec[..]).unwrap();
        // Check the proof
        assert!(verify_proof(
            &pvk,
            &proof,
            &witness[1..],
        ).unwrap());
        total_verifying += start.elapsed();
    }
    let proving_avg = total_proving / SAMPLES;
    let proving_avg = proving_avg.subsec_nanos() as f64 / 1_000_000_000f64
                      + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / SAMPLES;
    let verifying_avg = verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64
                      + (verifying_avg.as_secs() as f64);

    println!("Average proving time: {:?} seconds", proving_avg);
    println!("Average verifying time: {:?} seconds", verifying_avg);
}
