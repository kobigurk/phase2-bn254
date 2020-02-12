use bellman_ce::pairing::bn256::Bn256;
use powersoftau::{
    batched_accumulator::BatchedAccumulator,
    parameters::{CeremonyParams, CheckForCorrectness, CurveKind, UseCompression},
    utils::reduced_hash,
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
    let parameters = CeremonyParams::new(
        CurveKind::Bn256,
        10, // here we use 10 since it's the reduced ceremony
        21,
    );

    // Try to load `./challenge` from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open("challenge")
        .expect("unable open `./challenge` in this directory");
    let challenge_readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    let current_accumulator = BatchedAccumulator::<Bn256>::deserialize(
        &challenge_readable_map,
        CheckForCorrectness::Yes,
        UseCompression::No,
        &parameters,
    )
    .expect("unable to read compressed accumulator");

    let mut reduced_accumulator = BatchedAccumulator::<Bn256>::empty(&parameters);
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
        .open("reduced_challenge")
        .expect("unable to create `./reduced_challenge` in this directory");

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
        28, // this is the full size of the hash
        parameters.size as u8,
    );
    (&mut writable_map[0..])
        .write_all(hash.as_slice())
        .expect("unable to write a default hash to mmap");
    writable_map
        .flush()
        .expect("unable to write reduced hash to `./reduced_challenge`");

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
    let contribution_hash = BatchedAccumulator::<Bn256>::calculate_hash(&output_readonly);

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
