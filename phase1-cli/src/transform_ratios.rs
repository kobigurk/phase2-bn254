use phase1::{Phase1, Phase1Parameters};
use setup_utils::{calculate_hash, print_hash, CheckForCorrectness, UseCompression};

use algebra::PairingEngine as Engine;

use memmap::*;
use std::fs::OpenOptions;
use tracing::info;

pub fn transform_ratios<T: Engine + Sync>(
    response_filename: &str,
    check_input_correctness: CheckForCorrectness,
    parameters: &Phase1Parameters<T>,
) {
    info!(
        "Will verify and decompress a contribution to accumulator for 2^{} powers of tau",
        parameters.total_size_in_log2
    );

    // Try to load response file from disk.
    let response_reader = OpenOptions::new()
        .read(true)
        .open(response_filename)
        .expect("unable open response file in this directory");

    {
        let parameters = Phase1Parameters::<T>::new_chunk(
            parameters.contribution_mode,
            0,
            parameters.powers_g1_length,
            parameters.proving_system,
            parameters.total_size_in_log2,
            parameters.batch_size,
        );
        let metadata = response_reader
            .metadata()
            .expect("unable to get filesystem metadata for response file");
        let expected_response_length = parameters.accumulator_size;
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

    let response_hash = calculate_hash(&response_readable_map);

    info!("Hash of the response file for verification:");
    print_hash(&response_hash);

    // check that it follows the protocol
    info!("Verifying a contribution to contain proper powers and correspond to the public key...");

    let res = Phase1::aggregate_verification(
        (&response_readable_map, UseCompression::No, check_input_correctness),
        &parameters,
    );

    if let Err(e) = res {
        info!("Verification failed: {}", e);
        panic!("INVALID CONTRIBUTION!!!");
    } else {
        info!("Verification succeeded!");
    }
}
