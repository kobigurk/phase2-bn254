use phase2::parameters::MPCParameters;
use setup_utils::{calculate_hash, print_hash, CheckForCorrectness, UseCompression};

use algebra::{bw6_761::Fr, CanonicalSerialize, BW6_761};
use r1cs_core::ConstraintSynthesizer;
use r1cs_core::{ConstraintSystem, SynthesisMode};

use epoch_snark::ValidatorSetUpdate;
use memmap::*;
use std::{fs::OpenOptions, io::Write};
use tracing::info;

const COMPRESS_NEW_CHALLENGE: UseCompression = UseCompression::No;

pub fn new_challenge(
    challenge_filename: &str,
    challenge_hash_filename: &str,
    chunk_size: usize,
    phase1_filename: &str,
    phase1_powers: usize,
    num_validators: usize,
    num_epochs: usize,
) -> usize {
    info!("Generating phase 2");

    let reader = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&phase1_filename)
        .expect("unable open phase 1 file in this directory");
    let mut phase1_readable_map = unsafe {
        MmapOptions::new()
            .map_mut(&reader)
            .expect("unable to create a memory map for input")
    };

    let c = ValidatorSetUpdate::empty(num_validators, num_epochs, 0, None);
    let counter = ConstraintSystem::<Fr>::new_ref();
    counter.set_mode(SynthesisMode::Setup);
    info!("About to generate constraints");
    c.clone().generate_constraints(counter.clone()).unwrap();
    info!("Finished generating constraints");
    let phase2_size = std::cmp::max(
        counter.num_constraints(),
        counter.num_witness_variables() + counter.num_instance_variables(),
    )
    .next_power_of_two();

    let (full_mpc_parameters, query_parameters, all_mpc_parameters) =
        MPCParameters::<BW6_761>::new_from_buffer_chunked(
            c,
            &mut phase1_readable_map,
            UseCompression::No,
            CheckForCorrectness::No,
            1 << phase1_powers,
            phase2_size,
            chunk_size,
        )
        .unwrap();

    let mut serialized_mpc_parameters = vec![];
    full_mpc_parameters
        .write(&mut serialized_mpc_parameters, COMPRESS_NEW_CHALLENGE)
        .unwrap();

    let mut serialized_query_parameters = vec![];
    match COMPRESS_NEW_CHALLENGE {
        UseCompression::No => query_parameters.serialize_uncompressed(&mut serialized_query_parameters),
        UseCompression::Yes => query_parameters.serialize(&mut serialized_query_parameters),
    }
    .unwrap();

    let contribution_hash = {
        std::fs::File::create(format!("{}.full", challenge_filename))
            .expect("unable to open new challenge hash file")
            .write_all(&serialized_mpc_parameters)
            .expect("unable to write serialized mpc parameters");
        // Get the hash of the contribution, so the user can compare later
        calculate_hash(&serialized_mpc_parameters)
    };

    std::fs::File::create(format!("{}.query", challenge_filename))
        .expect("unable to open new challenge hash file")
        .write_all(&serialized_query_parameters)
        .expect("unable to write serialized mpc parameters");

    for (i, chunk) in all_mpc_parameters.iter().enumerate() {
        let mut serialized_chunk = vec![];
        chunk
            .write(&mut serialized_chunk, COMPRESS_NEW_CHALLENGE)
            .expect("unable to write chunk");
        std::fs::File::create(format!("{}.{}", challenge_filename, i))
            .expect("unable to open new challenge hash file")
            .write_all(&serialized_chunk)
            .expect("unable to write serialized mpc parameters");
    }

    std::fs::File::create(challenge_hash_filename)
        .expect("unable to open new challenge hash file")
        .write_all(contribution_hash.as_slice())
        .expect("unable to write new challenge hash");

    info!("Empty contribution is formed with a hash:");
    print_hash(&contribution_hash);
    info!("Wrote a fresh accumulator to challenge file");
    all_mpc_parameters.len()
}
