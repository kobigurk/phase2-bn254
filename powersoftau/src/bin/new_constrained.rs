use powersoftau::batched_accumulator::BatchedAccumulator;
use powersoftau::parameters::UseCompression;
use powersoftau::utils::{blank_hash, calculate_hash};

use bellman_ce::pairing::bn256::Bn256;
use memmap::*;
use std::fs::OpenOptions;
use std::io::Write;

use powersoftau::parameters::CeremonyParams;

const COMPRESS_NEW_CHALLENGE: UseCompression = UseCompression::No;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        println!("Usage: \n<challenge_file> <ceremony_size> <batch_size>");
        std::process::exit(exitcode::USAGE);
    }
    let challenge_filename = &args[1];
    let circuit_power = args[2].parse().expect("could not parse circuit power");
    let batch_size = args[3].parse().expect("could not parse batch size");

    let parameters = CeremonyParams::<Bn256>::new(circuit_power, batch_size);

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
    for line in hash.as_slice().chunks(16) {
        print!("\t");
        for section in line.chunks(4) {
            for b in section {
                print!("{:02x}", b);
            }
            print!(" ");
        }
        println!();
    }

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

    for line in contribution_hash.as_slice().chunks(16) {
        print!("\t");
        for section in line.chunks(4) {
            for b in section {
                print!("{:02x}", b);
            }
            print!(" ");
        }
        println!();
    }

    println!("Wrote a fresh accumulator to challenge file");
}
