use phase1::{Phase1, Phase1Parameters, PublicKey};
use setup_utils::{calculate_hash, print_hash, CheckForCorrectness, UseCompression};
use zexe_algebra::PairingEngine as Engine;

use memmap::*;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
};
use tracing::info;

const PREVIOUS_CHALLENGE_IS_COMPRESSED: UseCompression = UseCompression::No;
const CONTRIBUTION_IS_COMPRESSED: UseCompression = UseCompression::Yes;
const COMPRESS_NEW_CHALLENGE: UseCompression = UseCompression::No;

pub fn transform_pok_and_correctness<T: Engine + Sync>(
    challenge_filename: &str,
    challenge_hash_filename: &str,
    response_filename: &str,
    response_hash_filename: &str,
    new_challenge_filename: &str,
    new_challenge_hash_filename: &str,
    parameters: &Phase1Parameters<T>,
) {
    info!(
        "Will verify and decompress a contribution to accumulator for 2^{} powers of tau",
        parameters.total_size_in_log2
    );

    // Try to load challenge file from disk.
    let challenge_reader = OpenOptions::new()
        .read(true)
        .open(challenge_filename)
        .expect("unable open challenge file in this directory");

    {
        let metadata = challenge_reader
            .metadata()
            .expect("unable to get filesystem metadata for challenge file");
        let expected_challenge_length = match PREVIOUS_CHALLENGE_IS_COMPRESSED {
            UseCompression::Yes => parameters.contribution_size - parameters.public_key_size,
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

    let challenge_readable_map = unsafe {
        MmapOptions::new()
            .map(&challenge_reader)
            .expect("unable to create a memory map for input")
    };

    // Try to load response file from disk.
    let response_reader = OpenOptions::new()
        .read(true)
        .open(response_filename)
        .expect("unable open response file in this directory");

    {
        let metadata = response_reader
            .metadata()
            .expect("unable to get filesystem metadata for response file");
        let expected_response_length = match CONTRIBUTION_IS_COMPRESSED {
            UseCompression::Yes => parameters.contribution_size,
            UseCompression::No => parameters.accumulator_size + parameters.public_key_size,
        };
        if metadata.len() != (expected_response_length as u64) {
            panic!(
                "The size of response file should be {}, but it's {}, so something isn't right.",
                expected_response_length,
                metadata.len()
            );
        }
    }

    let response_readable_map = unsafe {
        MmapOptions::new()
            .map(&response_reader)
            .expect("unable to create a memory map for input")
    };

    info!("Calculating previous challenge hash...");

    // Check that contribution is correct

    let current_accumulator_hash = calculate_hash(&challenge_readable_map);
    std::fs::File::create(challenge_hash_filename)
        .expect("unable to open current accumulator hash file")
        .write_all(current_accumulator_hash.as_slice())
        .expect("unable to write current accumulator hash");

    info!("Hash of the `challenge` file for verification:");
    print_hash(&current_accumulator_hash);

    // Check the hash chain - a new response must be based on the previous challenge!
    {
        let mut response_challenge_hash = [0; 64];
        let mut memory_slice = response_readable_map
            .get(0..64)
            .expect("must read point data from file");
        memory_slice
            .read_exact(&mut response_challenge_hash)
            .expect("couldn't read hash of challenge file from response file");

        info!("`response` was based on the hash:");
        print_hash(&response_challenge_hash);

        if &response_challenge_hash[..] != current_accumulator_hash.as_slice() {
            panic!("Hash chain failure. This is not the right response.");
        }
    }

    let response_hash = calculate_hash(&response_readable_map);
    std::fs::File::create(response_hash_filename)
        .expect("unable to open response hash file")
        .write_all(response_hash.as_slice())
        .expect("unable to write response hash");

    info!("Hash of the response file for verification:");
    print_hash(&response_hash);

    // get the contributor's public key
    let public_key = PublicKey::read(&response_readable_map, CONTRIBUTION_IS_COMPRESSED, &parameters)
        .expect("wasn't able to deserialize the response file's public key");

    // check that it follows the protocol

    info!("Verifying a contribution to contain proper powers and correspond to the public key...");

    let res = Phase1::verification(
        &challenge_readable_map,
        &response_readable_map,
        &public_key,
        current_accumulator_hash.as_slice(),
        PREVIOUS_CHALLENGE_IS_COMPRESSED,
        CONTRIBUTION_IS_COMPRESSED,
        CheckForCorrectness::No,
        CheckForCorrectness::Full,
        &parameters,
    );

    if let Err(e) = res {
        info!("Verification failed: {}", e);
        panic!("INVALID CONTRIBUTION!!!");
    } else {
        info!("Verification succeeded!");
    }

    if COMPRESS_NEW_CHALLENGE == UseCompression::Yes {
        info!("Don't need to recompress the contribution, please copy response file as new challenge");
    } else {
        info!("Verification succeeded! Writing to new challenge file...");

        // Create new challenge file in this directory
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(new_challenge_filename)
            .expect("unable to create new challenge file in this directory");

        // Recomputation strips the public key and uses hashing to link with the previous contribution after decompression
        writer
            .set_len(parameters.accumulator_size as u64)
            .expect("must make output file large enough");

        let mut writable_map = unsafe {
            MmapOptions::new()
                .map_mut(&writer)
                .expect("unable to create a memory map for output")
        };

        {
            (&mut writable_map[0..])
                .write_all(response_hash.as_slice())
                .expect("unable to write a default hash to mmap");

            writable_map
                .flush()
                .expect("unable to write hash to new challenge file");
        }

        Phase1::decompress(
            &response_readable_map,
            &mut writable_map,
            CheckForCorrectness::No,
            &parameters,
        )
        .expect("must decompress a response for a new challenge");

        writable_map.flush().expect("must flush the memory map");

        let new_challenge_readable_map = writable_map.make_read_only().expect("must make a map readonly");

        let recompressed_hash = calculate_hash(&new_challenge_readable_map);

        std::fs::File::create(new_challenge_hash_filename)
            .expect("unable to open new challenge hash file")
            .write_all(recompressed_hash.as_slice())
            .expect("unable to write new challenge hash");

        info!("Here's the BLAKE2b hash of the decompressed participant's response as new_challenge file:");
        print_hash(&recompressed_hash);
        info!("Done! new challenge file contains the new challenge file. The other files");
        info!("were left alone.");
    }
}
