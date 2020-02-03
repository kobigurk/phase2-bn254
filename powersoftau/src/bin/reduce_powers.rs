extern crate powersoftau;
extern crate rand;
extern crate blake2;
extern crate byteorder;
extern crate bellman_ce;

use bellman_ce::pairing::bn256::Bn256;
use powersoftau::bn256::Bn256CeremonyParameters;
use powersoftau::batched_accumulator::*;
use powersoftau::parameters::UseCompression;
use powersoftau::utils::reduced_hash;
use powersoftau::*;

use crate::parameters::*;

use std::fs::OpenOptions;
use std::io::Write;

use memmap::*;

#[derive(Clone)]
pub struct Bn256ReducedCeremonyParameters {

}

impl PowersOfTauParameters for Bn256ReducedCeremonyParameters {
    const REQUIRED_POWER: usize = 10;

    // This ceremony is based on the BN256 elliptic curve construction.
    const G1_UNCOMPRESSED_BYTE_SIZE: usize = 64;
    const G2_UNCOMPRESSED_BYTE_SIZE: usize = 128;
    const G1_COMPRESSED_BYTE_SIZE: usize = 32;
    const G2_COMPRESSED_BYTE_SIZE: usize = 64;
}

const fn num_bits<T>() -> usize { std::mem::size_of::<T>() * 8 }

pub fn log_2(x: u64) -> u32 {
    assert!(x > 0);
    num_bits::<u64>() as u32 - x.leading_zeros() - 1
}

fn main() {
    // Try to load `./challenge` from disk.
    let reader = OpenOptions::new()
                            .read(true)
                            .open("challenge")
                            .expect("unable open `./challenge` in this directory");
    let challenge_readable_map = unsafe { MmapOptions::new().map(&reader).expect("unable to create a memory map for input") };

    let current_accumulator = BatchedAccumulator::<Bn256, Bn256CeremonyParameters>::deserialize(
        &challenge_readable_map,
        CheckForCorrectness::Yes,
        UseCompression::No,
    ).expect("unable to read compressed accumulator");

    let mut reduced_accumulator = BatchedAccumulator::<Bn256, Bn256ReducedCeremonyParameters>::empty();
    reduced_accumulator.tau_powers_g1 = current_accumulator.tau_powers_g1[..Bn256ReducedCeremonyParameters::TAU_POWERS_G1_LENGTH].to_vec();
    reduced_accumulator.tau_powers_g2 = current_accumulator.tau_powers_g2[..Bn256ReducedCeremonyParameters::TAU_POWERS_LENGTH].to_vec();
    reduced_accumulator.alpha_tau_powers_g1 = current_accumulator.alpha_tau_powers_g1[..Bn256ReducedCeremonyParameters::TAU_POWERS_LENGTH].to_vec();
    reduced_accumulator.beta_tau_powers_g1 = current_accumulator.beta_tau_powers_g1[..Bn256ReducedCeremonyParameters::TAU_POWERS_LENGTH].to_vec();
    reduced_accumulator.beta_g2 = current_accumulator.beta_g2;

    let writer = OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create_new(true)
                            .open("reduced_challenge").expect("unable to create `./reduced_challenge` in this directory");



    // Recomputation stips the public key and uses hashing to link with the previous contibution after decompression
    writer.set_len(Bn256ReducedCeremonyParameters::ACCUMULATOR_BYTE_SIZE as u64).expect("must make output file large enough");

    let mut writable_map = unsafe { MmapOptions::new().map_mut(&writer).expect("unable to create a memory map for output") };

    let hash = reduced_hash(Bn256CeremonyParameters::REQUIRED_POWER as u8, Bn256ReducedCeremonyParameters::REQUIRED_POWER as u8);
    (&mut writable_map[0..]).write(hash.as_slice()).expect("unable to write a default hash to mmap");
    writable_map.flush().expect("unable to write reduced hash to `./reduced_challenge`");

    println!("Reduced hash for a reduced challenge:");
    for line in hash.as_slice().chunks(16) {
        print!("\t");
        for section in line.chunks(4) {
            for b in section {
                print!("{:02x}", b);
            }
            print!(" ");
        }
        println!("");
    }

    reduced_accumulator.serialize(&mut writable_map, UseCompression::No).unwrap();

    // Get the hash of the contribution, so the user can compare later
    let output_readonly = writable_map.make_read_only().expect("must make a map readonly");
    let contribution_hash = BatchedAccumulator::<Bn256, Bn256ReducedCeremonyParameters>::calculate_hash(&output_readonly);

    println!("Reduced contribution is formed with a hash:");

    for line in contribution_hash.as_slice().chunks(16) {
        print!("\t");
        for section in line.chunks(4) {
            for b in section {
                print!("{:02x}", b);
            }
            print!(" ");
        }
        println!("");
    }

    println!("Wrote a reduced accumulator to `./challenge`");
}
