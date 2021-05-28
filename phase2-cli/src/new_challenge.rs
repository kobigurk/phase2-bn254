use phase2::load_circuit::Matrices;
use phase2::parameters::MPCParameters;
use setup_utils::{calculate_hash, print_hash, CheckForCorrectness, UseCompression};

use crate::COMPRESS_CONTRIBUTE_INPUT;
use algebra::{CanonicalDeserialize, CanonicalSerialize, BW6_761};
use memmap::*;
use std::{fs::File, fs::OpenOptions, io::Read, io::Write};
use tracing::info;

pub fn new_challenge(
    challenge_filename: &str,
    challenge_hash_filename: &str,
    challenge_list_filename: &str,
    chunk_size: usize,
    phase1_filename: &str,
    phase1_powers: usize,
    circuit_filename: &str,
) -> usize {
    info!("Generating phase 2");

    let mut file = File::open(circuit_filename).unwrap();
    let mut buffer = Vec::<u8>::new();
    file.read_to_end(&mut buffer).unwrap();
    let m = Matrices::<BW6_761>::deserialize(&*buffer).unwrap();

    info!("Loaded circuit with {} constraints", m.num_constraints);

    let phase2_size =
        std::cmp::max(m.num_constraints, m.num_witness_variables + m.num_instance_variables).next_power_of_two();

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

    let (full_mpc_parameters, query_parameters, all_mpc_parameters) =
        MPCParameters::<BW6_761>::new_from_buffer_chunked(
            m,
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
        .write(&mut serialized_mpc_parameters, COMPRESS_CONTRIBUTE_INPUT)
        .unwrap();

    let mut serialized_query_parameters = vec![];
    match COMPRESS_CONTRIBUTE_INPUT {
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

    let mut challenge_list_file =
        std::fs::File::create(challenge_list_filename).expect("unable to open new challenge list file");

    for (i, chunk) in all_mpc_parameters.iter().enumerate() {
        let mut serialized_chunk = vec![];
        chunk
            .write(&mut serialized_chunk, COMPRESS_CONTRIBUTE_INPUT)
            .expect("unable to write chunk");
        std::fs::File::create(format!("{}.{}", challenge_filename, i))
            .expect("unable to open new challenge hash file")
            .write_all(&serialized_chunk)
            .expect("unable to write serialized mpc parameters");
        challenge_list_file
            .write(format!("{}.{}\n", challenge_filename, i).as_bytes())
            .expect("unable to write challenge list");
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
