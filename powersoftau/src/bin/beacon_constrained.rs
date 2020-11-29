extern crate hex;
use powersoftau::{
    batched_accumulator::BatchedAccumulator,
    keypair::keypair,
    parameters::{CeremonyParams, CheckForCorrectness, UseCompression},
    utils::calculate_hash,
};

use bellman_ce::pairing::bn256::Bn256;
use memmap::MmapOptions;
use std::fs::OpenOptions;

use std::io::Write;
extern crate hex_literal;

const INPUT_IS_COMPRESSED: UseCompression = UseCompression::No;
const COMPRESS_THE_OUTPUT: UseCompression = UseCompression::Yes;
const CHECK_INPUT_CORRECTNESS: CheckForCorrectness = CheckForCorrectness::No;

#[allow(clippy::modulo_one)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        println!("Usage: \n<challenge_file> <response_file> <circuit_power> <batch_size> <beacon_hash> <num_iterations_exp>");
        std::process::exit(exitcode::USAGE);
    }
    let challenge_filename = &args[1];
    let response_filename = &args[2];
    let circuit_power = args[3].parse().expect("could not parse circuit power");
    let batch_size = args[4].parse().expect("could not parse batch size");
    let beacon_hash = &args[5];
    let num_iterations_exp = &args[6].parse::<usize>().unwrap();

    if *num_iterations_exp < 10 || *num_iterations_exp > 63 {
        println!("in_num_iterations_exp should be in [10, 63] range");
        std::process::exit(exitcode::DATAERR);
    }

    let parameters = CeremonyParams::<Bn256>::new(circuit_power, batch_size);

    println!(
        "Will contribute a random beacon to accumulator for 2^{} powers of tau",
        parameters.size,
    );
    println!(
        "In total will generate up to {} powers",
        parameters.powers_g1_length,
    );

    // Create an RNG based on the outcome of the random beacon
    let mut rng = {
        use byteorder::{BigEndian, ReadBytesExt};
        use crypto::digest::Digest;
        use crypto::sha2::Sha256;
        use rand::chacha::ChaChaRng;
        use rand::SeedableRng;

        let mut cur_hash = hex::decode(beacon_hash).unwrap();

        // Performs 2^n hash iterations over it
        let n: usize = *num_iterations_exp;

        for i in 0..(1u64 << n) {
            // Print 1024 of the interstitial states
            // so that verification can be
            // parallelized

            if i % (1u64 << (n - 10)) == 0 {
                print!("{}: ", i);
                for b in cur_hash.iter() {
                    print!("{:02x}", b);
                }
                println!();
            }

            let mut h = Sha256::new();
            h.input(&cur_hash);
            h.result(&mut cur_hash);
        }

        print!("Final result of beacon: ");
        for b in cur_hash.iter() {
            print!("{:02x}", b);
        }
        println!();

        let mut digest = &cur_hash[..];

        let mut seed = [0u32; 8];
        for s in &mut seed {
            *s = digest
                .read_u32::<BigEndian>()
                .expect("digest is large enough for this to work");
        }

        ChaChaRng::from_seed(&seed)
    };

    println!("Done creating a beacon RNG");

    // Try to load challenge file from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open(challenge_filename)
        .expect("unable open challenge file in this directory");

    {
        let metadata = reader
            .metadata()
            .expect("unable to get filesystem metadata for challenge file");
        let expected_challenge_length = match INPUT_IS_COMPRESSED {
            UseCompression::Yes => parameters.contribution_size,
            UseCompression::No => parameters.accumulator_size,
        };

        if metadata.len() != (expected_challenge_length as u64) {
            panic!(
                "The size of challenge file should be {}, but it's {}, so something isn't right.",
                expected_challenge_length,
                metadata.len()
            );
        }
    }

    let readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    // Create response file in this directory
    let writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(response_filename)
        .expect("unable to create response file in this directory");

    let required_output_length = match COMPRESS_THE_OUTPUT {
        UseCompression::Yes => parameters.contribution_size,
        UseCompression::No => parameters.accumulator_size + parameters.public_key_size,
    };

    writer
        .set_len(required_output_length as u64)
        .expect("must make output file large enough");

    let mut writable_map = unsafe {
        MmapOptions::new()
            .map_mut(&writer)
            .expect("unable to create a memory map for output")
    };

    println!("Calculating previous contribution hash...");

    let current_accumulator_hash = calculate_hash(&readable_map);

    {
        println!("Contributing on top of the hash:");
        for line in current_accumulator_hash.as_slice().chunks(16) {
            print!("\t");
            for section in line.chunks(4) {
                for b in section {
                    print!("{:02x}", b);
                }
                print!(" ");
            }
            println!();
        }

        (&mut writable_map[0..])
            .write_all(current_accumulator_hash.as_slice())
            .expect("unable to write a challenge hash to mmap");

        writable_map
            .flush()
            .expect("unable to write hash to response file");
    }

    // Construct our keypair using the RNG we created above
    let (pubkey, privkey) = keypair(&mut rng, current_accumulator_hash.as_ref());

    // Perform the transformation
    println!("Computing and writing your contribution, this could take a while...");

    // this computes a transformation and writes it
    BatchedAccumulator::transform(
        &readable_map,
        &mut writable_map,
        INPUT_IS_COMPRESSED,
        COMPRESS_THE_OUTPUT,
        CHECK_INPUT_CORRECTNESS,
        &privkey,
        &parameters,
    )
    .expect("must transform with the key");
    println!("Finishing writing your contribution to response file...");

    // Write the public key
    pubkey
        .write(&mut writable_map, COMPRESS_THE_OUTPUT, &parameters)
        .expect("unable to write public key");

    // Get the hash of the contribution, so the user can compare later
    let output_readonly = writable_map
        .make_read_only()
        .expect("must make a map readonly");
    let contribution_hash = calculate_hash(&output_readonly);

    print!(
        "Done!\n\n\
              Your contribution has been written to response file\n\n\
              The BLAKE2b hash of response file is:\n"
    );

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

    println!("Thank you for your participation, much appreciated! :)");
}
