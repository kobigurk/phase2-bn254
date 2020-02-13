use crate::batched_accumulator::*;
use crate::parameters::CeremonyParams;
use bellman_ce::pairing::{CurveAffine, CurveProjective, Engine};

use crate::keypair::*;
use crate::parameters::*;
use crate::utils::*;

use bellman_ce::domain::{EvaluationDomain, Point};
use bellman_ce::worker::Worker;

use std::fs::{remove_file, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;

use memmap::*;

// Computes the hash of the challenge file for the player,
// given the current state of the accumulator and the last
// response file hash.
fn get_challenge_file_hash<E: Engine>(
    acc: &mut BatchedAccumulator<E>,
    last_response_file_hash: &[u8; 64],
    is_initial: bool,
) -> [u8; 64] {
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    let parameters = acc.parameters;

    let file_name = "tmp_challenge_file_hash";

    if Path::new(file_name).exists() {
        remove_file(file_name).unwrap();
    }
    {
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(file_name)
            .expect("unable to create temporary tmp_challenge_file_hash");

        writer
            .set_len(parameters.accumulator_size as u64)
            .expect("must make output file large enough");
        let mut writable_map = unsafe {
            MmapOptions::new()
                .map_mut(&writer)
                .expect("unable to create a memory map for output")
        };

        (&mut writable_map[0..])
            .write_all(&last_response_file_hash[..])
            .expect("unable to write a default hash to mmap");
        writable_map
            .flush()
            .expect("unable to write blank hash to challenge file");

        if is_initial {
            BatchedAccumulator::generate_initial(&mut writable_map, UseCompression::No, parameters)
                .expect("generation of initial accumulator is successful");
        } else {
            acc.serialize(&mut writable_map, UseCompression::No, parameters)
                .unwrap();
        }

        writable_map.flush().expect("must flush the memory map");
    }

    let mut challenge_reader = OpenOptions::new()
        .read(true)
        .open(file_name)
        .expect("unable to open temporary tmp_challenge_file_hash");

    let mut contents = vec![];
    challenge_reader.read_to_end(&mut contents).unwrap();

    sink.write_all(&contents).unwrap();

    let mut tmp = [0; 64];
    tmp.copy_from_slice(sink.into_hash().as_slice());

    tmp
}

// Computes the hash of the response file, given the new
// accumulator, the player's public key, and the challenge
// file's hash.
fn get_response_file_hash<E: Engine>(
    acc: &mut BatchedAccumulator<E>,
    pubkey: &PublicKey<E>,
    last_challenge_file_hash: &[u8; 64],
) -> [u8; 64] {
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    let parameters = acc.parameters;

    let file_name = "tmp_response_file_hash";
    if Path::new(file_name).exists() {
        remove_file(file_name).unwrap();
    }
    {
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(file_name)
            .expect("unable to create temporary tmp_response_file_hash");

        writer
            .set_len(parameters.contribution_size as u64)
            .expect("must make output file large enough");
        let mut writable_map = unsafe {
            MmapOptions::new()
                .map_mut(&writer)
                .expect("unable to create a memory map for output")
        };

        (&mut writable_map[0..])
            .write_all(&last_challenge_file_hash[..])
            .expect("unable to write a default hash to mmap");
        writable_map
            .flush()
            .expect("unable to write blank hash to challenge file");

        acc.serialize(&mut writable_map, UseCompression::Yes, parameters)
            .unwrap();

        pubkey
            .write(&mut writable_map, UseCompression::Yes, parameters)
            .expect("unable to write public key");
        writable_map.flush().expect("must flush the memory map");
    }

    let mut challenge_reader = OpenOptions::new()
        .read(true)
        .open(file_name)
        .expect("unable to open temporary tmp_response_file_hash");

    let mut contents = vec![];
    challenge_reader.read_to_end(&mut contents).unwrap();

    sink.write_all(&contents).unwrap();

    let mut tmp = [0; 64];
    tmp.copy_from_slice(sink.into_hash().as_slice());

    tmp
}

fn new_accumulator_for_verify<T: Engine>(parameters: &CeremonyParams<T>) -> BatchedAccumulator<T> {
    let file_name = "tmp_initial_challenge";
    {
        if Path::new(file_name).exists() {
            remove_file(file_name).unwrap();
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(file_name)
            .expect("unable to create `./tmp_initial_challenge`");

        let expected_challenge_length = parameters.accumulator_size;
        file.set_len(expected_challenge_length as u64)
            .expect("unable to allocate large enough file");

        let mut writable_map = unsafe {
            MmapOptions::new()
                .map_mut(&file)
                .expect("unable to create a memory map")
        };
        BatchedAccumulator::generate_initial(&mut writable_map, UseCompression::No, &parameters)
            .expect("generation of initial accumulator is successful");
        writable_map
            .flush()
            .expect("unable to flush memmap to disk");
    }

    let reader = OpenOptions::new()
        .read(true)
        .open(file_name)
        .expect("unable open transcript file in this directory");

    let readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    BatchedAccumulator::deserialize(
        &readable_map,
        CheckForCorrectness::Yes,
        UseCompression::No,
        &parameters,
    )
    .expect("unable to read uncompressed accumulator")
}

pub fn verify<E: Engine>(transcript_filename: &str, parameters: &CeremonyParams<E>) {
    // Try to load transcript file from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open(transcript_filename)
        .expect("unable open transcript file in this directory");

    let transcript_readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    // Initialize the accumulator
    let mut current_accumulator = new_accumulator_for_verify(&parameters);

    // The "last response file hash" is just a blank BLAKE2b hash
    // at the beginning of the hash chain.
    let mut last_response_file_hash = [0; 64];
    last_response_file_hash.copy_from_slice(blank_hash().as_slice());

    // There were 89 rounds.
    for i in 0..2 {
        // Compute the hash of the challenge file that the player
        // should have received.

        let file_name = "tmp_response";
        if Path::new(file_name).exists() {
            remove_file(file_name).unwrap();
        }

        let memory_slice = transcript_readable_map
            .get(i * parameters.contribution_size..(i + 1) * parameters.contribution_size)
            .expect("must read point data from file");
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(file_name)
            .expect("unable to create temporary tmp_response");

        writer
            .set_len(parameters.contribution_size as u64)
            .expect("must make output file large enough");
        let mut writable_map = unsafe {
            MmapOptions::new()
                .map_mut(&writer)
                .expect("unable to create a memory map for output")
        };

        (&mut writable_map[0..])
            .write_all(&memory_slice[..])
            .expect("unable to write a default hash to mmap");
        writable_map.flush().expect("must flush the memory map");

        let response_readable_map = writable_map
            .make_read_only()
            .expect("must make a map readonly");

        let last_challenge_file_hash =
            get_challenge_file_hash(&mut current_accumulator, &last_response_file_hash, i == 0);

        // Deserialize the accumulator provided by the player in
        // their response file. It's stored in the transcript in
        // uncompressed form so that we can more efficiently
        // deserialize it.

        let mut response_file_accumulator = BatchedAccumulator::deserialize(
            &response_readable_map,
            CheckForCorrectness::Yes,
            UseCompression::Yes,
            &parameters,
        )
        .expect("unable to read uncompressed accumulator");

        let response_file_pubkey =
            PublicKey::read(&response_readable_map, UseCompression::Yes, &parameters).unwrap();
        // Compute the hash of the response file. (we had it in uncompressed
        // form in the transcript, but the response file is compressed to save
        // participants bandwidth.)
        last_response_file_hash = get_response_file_hash(
            &mut response_file_accumulator,
            &response_file_pubkey,
            &last_challenge_file_hash,
        );

        // Verify the transformation from the previous accumulator to the new
        // one. This also verifies the correctness of the accumulators and the
        // public keys, with respect to the transcript so far.
        if !verify_transform(
            &current_accumulator,
            &response_file_accumulator,
            &response_file_pubkey,
            &last_challenge_file_hash,
        ) {
            println!(" ... FAILED");
            panic!("INVALID RESPONSE FILE!");
        } else {
            println!();
        }

        current_accumulator = response_file_accumulator;
    }

    println!("Transcript OK!");

    let worker = &Worker::new();

    // Create the parameters for various 2^m circuit depths.
    let max_degree = log_2(current_accumulator.tau_powers_g2.len() as u64);
    for m in 0..=max_degree {
        let paramname = format!("phase1radix2m{}", m);
        println!("Creating {}", paramname);

        let degree = 1 << m;

        let mut g1_coeffs = EvaluationDomain::from_coeffs(
            current_accumulator.tau_powers_g1[0..degree]
                .iter()
                .map(|e| Point(e.into_projective()))
                .collect(),
        )
        .unwrap();

        let mut g2_coeffs = EvaluationDomain::from_coeffs(
            current_accumulator.tau_powers_g2[0..degree]
                .iter()
                .map(|e| Point(e.into_projective()))
                .collect(),
        )
        .unwrap();

        let mut g1_alpha_coeffs = EvaluationDomain::from_coeffs(
            current_accumulator.alpha_tau_powers_g1[0..degree]
                .iter()
                .map(|e| Point(e.into_projective()))
                .collect(),
        )
        .unwrap();

        let mut g1_beta_coeffs = EvaluationDomain::from_coeffs(
            current_accumulator.beta_tau_powers_g1[0..degree]
                .iter()
                .map(|e| Point(e.into_projective()))
                .collect(),
        )
        .unwrap();

        // This converts all of the elements into Lagrange coefficients
        // for later construction of interpolation polynomials
        g1_coeffs.ifft(&worker);
        g2_coeffs.ifft(&worker);
        g1_alpha_coeffs.ifft(&worker);
        g1_beta_coeffs.ifft(&worker);

        let g1_coeffs = g1_coeffs.into_coeffs();
        let g2_coeffs = g2_coeffs.into_coeffs();
        let g1_alpha_coeffs = g1_alpha_coeffs.into_coeffs();
        let g1_beta_coeffs = g1_beta_coeffs.into_coeffs();

        assert_eq!(g1_coeffs.len(), degree);
        assert_eq!(g2_coeffs.len(), degree);
        assert_eq!(g1_alpha_coeffs.len(), degree);
        assert_eq!(g1_beta_coeffs.len(), degree);

        // Remove the Point() wrappers

        let mut g1_coeffs = g1_coeffs.into_iter().map(|e| e.0).collect::<Vec<_>>();

        let mut g2_coeffs = g2_coeffs.into_iter().map(|e| e.0).collect::<Vec<_>>();

        let mut g1_alpha_coeffs = g1_alpha_coeffs.into_iter().map(|e| e.0).collect::<Vec<_>>();

        let mut g1_beta_coeffs = g1_beta_coeffs.into_iter().map(|e| e.0).collect::<Vec<_>>();

        // Batch normalize
        <E as Engine>::G1::batch_normalization(&mut g1_coeffs);
        <E as Engine>::G2::batch_normalization(&mut g2_coeffs);
        <E as Engine>::G1::batch_normalization(&mut g1_alpha_coeffs);
        <E as Engine>::G1::batch_normalization(&mut g1_beta_coeffs);

        // H query of Groth16 needs...
        // x^i * (x^m - 1) for i in 0..=(m-2) a.k.a.
        // x^(i + m) - x^i for i in 0..=(m-2)
        // for radix2 evaluation domains
        let mut h = Vec::with_capacity(degree - 1);
        for i in 0..(degree - 1) {
            let mut tmp = current_accumulator.tau_powers_g1[i + degree].into_projective();
            let mut tmp2 = current_accumulator.tau_powers_g1[i].into_projective();
            tmp2.negate();
            tmp.add_assign(&tmp2);

            h.push(tmp);
        }

        // Batch normalize this as well
        <E as Engine>::G1::batch_normalization(&mut h);

        // Create the parameter file
        let writer = OpenOptions::new()
            .read(false)
            .write(true)
            .create_new(true)
            .open(paramname)
            .expect("unable to create parameter file in this directory");

        let mut writer = BufWriter::new(writer);

        // Write alpha (in g1)
        // Needed by verifier for e(alpha, beta)
        // Needed by prover for A and C elements of proof
        writer
            .write_all(
                current_accumulator.alpha_tau_powers_g1[0]
                    .into_uncompressed()
                    .as_ref(),
            )
            .unwrap();

        // Write beta (in g1)
        // Needed by prover for C element of proof
        writer
            .write_all(
                current_accumulator.beta_tau_powers_g1[0]
                    .into_uncompressed()
                    .as_ref(),
            )
            .unwrap();

        // Write beta (in g2)
        // Needed by verifier for e(alpha, beta)
        // Needed by prover for B element of proof
        writer
            .write_all(current_accumulator.beta_g2.into_uncompressed().as_ref())
            .unwrap();

        // Lagrange coefficients in G1 (for constructing
        // LC/IC queries and precomputing polynomials for A)
        for coeff in g1_coeffs {
            // Was normalized earlier in parallel
            let coeff = coeff.into_affine();

            writer
                .write_all(coeff.into_uncompressed().as_ref())
                .unwrap();
        }

        // Lagrange coefficients in G2 (for precomputing
        // polynomials for B)
        for coeff in g2_coeffs {
            // Was normalized earlier in parallel
            let coeff = coeff.into_affine();

            writer
                .write_all(coeff.into_uncompressed().as_ref())
                .unwrap();
        }

        // Lagrange coefficients in G1 with alpha (for
        // LC/IC queries)
        for coeff in g1_alpha_coeffs {
            // Was normalized earlier in parallel
            let coeff = coeff.into_affine();

            writer
                .write_all(coeff.into_uncompressed().as_ref())
                .unwrap();
        }

        // Lagrange coefficients in G1 with beta (for
        // LC/IC queries)
        for coeff in g1_beta_coeffs {
            // Was normalized earlier in parallel
            let coeff = coeff.into_affine();

            writer
                .write_all(coeff.into_uncompressed().as_ref())
                .unwrap();
        }

        // Bases for H polynomial computation
        for coeff in h {
            // Was normalized earlier in parallel
            let coeff = coeff.into_affine();

            writer
                .write_all(coeff.into_uncompressed().as_ref())
                .unwrap();
        }
    }
}
