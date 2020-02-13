use bellman_ce::pairing::bn256::Bn256;
use powersoftau::{
    batched_accumulator::BatchedAccumulator,
    parameters::{CeremonyParams, CheckForCorrectness, UseCompression},
    utils::{calculate_hash, reduced_hash},
};

use std::fs::OpenOptions;
use std::io::Write;

use memmap::MmapOptions;

const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

pub fn log_2(x: u64) -> u32 {
    assert!(x > 0);
    num_bits::<u64>() as u32 - x.leading_zeros() - 1
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        println!("Usage: \n<challenge_filename> <reduced_challenge_filename> <original_circuit_power> <reduced_circuit_power> <batch_size>");
        std::process::exit(exitcode::USAGE);
    }
    let challenge_filename = &args[1];
    let reduced_challenge_filename = &args[2];
    let original_circuit_power = args[3].parse().expect("could not parse original circuit power");
    let reduced_circuit_power = args[4].parse().expect("could not parse reduced circuit power");
    let batch_size = args[5].parse().expect("could not parse batch size");

    let parameters = CeremonyParams::<Bn256>::new(reduced_circuit_power, batch_size);

    // Try to load the challenge from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open(challenge_filename)
        .expect("unable to open challenge in this directory");
    let challenge_readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    let current_accumulator = BatchedAccumulator::deserialize(
        &challenge_readable_map,
        CheckForCorrectness::Yes,
        UseCompression::No,
        &parameters,
    )
    .expect("unable to read compressed accumulator");

    let mut reduced_accumulator = BatchedAccumulator::empty(&parameters);
    reduced_accumulator.tau_powers_g1 =
        current_accumulator.tau_powers_g1[..parameters.powers_g1_length].to_vec();
    reduced_accumulator.tau_powers_g2 =
        current_accumulator.tau_powers_g2[..parameters.powers_length].to_vec();
    reduced_accumulator.alpha_tau_powers_g1 =
        current_accumulator.alpha_tau_powers_g1[..parameters.powers_length].to_vec();
    reduced_accumulator.beta_tau_powers_g1 =
        current_accumulator.beta_tau_powers_g1[..parameters.powers_length].to_vec();
    reduced_accumulator.beta_g2 = current_accumulator.beta_g2;

    let writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(reduced_challenge_filename)
        .expect("unable to create the reduced challenge in this directory");

    // Recomputation stips the public key and uses hashing to link with the previous contibution after decompression
    writer
        .set_len(parameters.accumulator_size as u64)
        .expect("must make output file large enough");

    let mut writable_map = unsafe {
        MmapOptions::new()
            .map_mut(&writer)
            .expect("unable to create a memory map for output")
    };

    let hash = reduced_hash(
        original_circuit_power,
        parameters.size as u8,
    );
    (&mut writable_map[0..])
        .write_all(hash.as_slice())
        .expect("unable to write a default hash to mmap");
    writable_map
        .flush()
        .expect("unable to write reduced hash to the reduced_challenge");

    println!("Reduced hash for a reduced challenge:");
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

    reduced_accumulator
        .serialize(&mut writable_map, UseCompression::No, &parameters)
        .unwrap();

    // Get the hash of the contribution, so the user can compare later
    let output_readonly = writable_map
        .make_read_only()
        .expect("must make a map readonly");
    let contribution_hash = calculate_hash(&output_readonly);

    println!("Reduced contribution is formed with a hash:");

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

    println!("Wrote a reduced accumulator to `./challenge`");
}
