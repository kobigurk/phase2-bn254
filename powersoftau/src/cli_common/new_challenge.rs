use crate::batched_accumulator::BatchedAccumulator;
use crate::parameters::{CeremonyParams, UseCompression};
use crate::utils::{blank_hash, calculate_hash, print_hash};

use memmap::*;
use std::fs::OpenOptions;
use std::io::Write;
use zexe_algebra::PairingEngine as Engine;

const COMPRESS_NEW_CHALLENGE: UseCompression = UseCompression::No;

pub fn new_challenge<T: Engine + Sync>(challenge_filename: &str, parameters: &CeremonyParams<T>) {
    println!(
        "Will generate an empty accumulator for 2^{} powers of tau",
        parameters.size
    );
    println!(
        "In total will generate up to {} powers",
        parameters.powers_g1_length
    );

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(challenge_filename)
        .expect("unable to create challenge file");

    let expected_challenge_length = match COMPRESS_NEW_CHALLENGE {
        UseCompression::Yes => parameters.contribution_size - parameters.public_key_size,
        UseCompression::No => parameters.accumulator_size,
    };

    file.set_len(expected_challenge_length as u64)
        .expect("unable to allocate large enough file");

    let mut writable_map = unsafe {
        MmapOptions::new()
            .map_mut(&file)
            .expect("unable to create a memory map")
    };

    // Write a blank BLAKE2b hash:
    let hash = blank_hash();
    (&mut writable_map[0..])
        .write_all(hash.as_slice())
        .expect("unable to write a default hash to mmap");
    writable_map
        .flush()
        .expect("unable to write blank hash to challenge file");

    println!("Blank hash for an empty challenge:");
    print_hash(&hash);

    BatchedAccumulator::generate_initial(&mut writable_map, COMPRESS_NEW_CHALLENGE, &parameters)
        .expect("generation of initial accumulator is successful");
    writable_map
        .flush()
        .expect("unable to flush memmap to disk");

    // Get the hash of the contribution, so the user can compare later
    let output_readonly = writable_map
        .make_read_only()
        .expect("must make a map readonly");
    let contribution_hash = calculate_hash(&output_readonly);

    println!("Empty contribution is formed with a hash:");
    print_hash(&contribution_hash);
    println!("Wrote a fresh accumulator to challenge file");
}
