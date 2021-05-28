use phase2::parameters::MPCParameters;
use setup_utils::{calculate_hash, print_hash, CheckForCorrectness, SubgroupCheckMode};

use algebra::BW6_761;

use crate::{COMBINED_IS_COMPRESSED, COMPRESS_CONTRIBUTE_INPUT, COMPRESS_CONTRIBUTE_OUTPUT};
use memmap::MmapOptions;
use std::fs::OpenOptions;
use std::io::Write;
use tracing::info;

pub fn verify(
    challenge_filename: &str,
    challenge_hash_filename: &str,
    check_input_correctness: CheckForCorrectness,
    response_filename: &str,
    response_hash_filename: &str,
    check_output_correctness: CheckForCorrectness,
    new_challenge_filename: &str,
    new_challenge_hash_filename: &str,
    subgroup_check_mode: SubgroupCheckMode,
    verifying_full_contribution: bool,
) {
    info!("Verifying phase 2");

    let challenge_contents = std::fs::read(challenge_filename).expect("should have read challenge");
    let challenge_hash = calculate_hash(&challenge_contents);
    std::fs::File::create(challenge_hash_filename)
        .expect("unable to open current accumulator hash file")
        .write_all(&challenge_hash)
        .expect("unable to write current accumulator hash");

    info!("`challenge` file contains decompressed points and has a hash:");
    print_hash(&challenge_hash);

    let parameters_before = MPCParameters::<BW6_761>::read_fast(
        challenge_contents.as_slice(),
        COMPRESS_CONTRIBUTE_INPUT,
        check_input_correctness,
        true,
        subgroup_check_mode,
    )
    .expect("should have read parameters");

    let response_contents = std::fs::read(response_filename).expect("should have read response");
    let response_hash = calculate_hash(&response_contents);
    std::fs::File::create(response_hash_filename)
        .expect("unable to open current accumulator hash file")
        .write_all(&response_hash)
        .expect("unable to write current accumulator hash");

    info!("`response` file contains decompressed points and has a hash:");
    print_hash(&response_hash);

    let after_compressed = if verifying_full_contribution {
        COMBINED_IS_COMPRESSED
    } else {
        COMPRESS_CONTRIBUTE_OUTPUT
    };
    let parameters_after = MPCParameters::<BW6_761>::read_fast(
        response_contents.as_slice(),
        after_compressed,
        check_output_correctness,
        true,
        subgroup_check_mode,
    )
    .expect("should have read parameters");

    let writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(new_challenge_filename)
        .expect("unable to create new challenge file in this directory");
    parameters_after
        .write(writer, COMPRESS_CONTRIBUTE_INPUT)
        .expect("unable to write new challenge file");

    // Read new challenge to create hash
    let new_challenge_reader = OpenOptions::new()
        .read(true)
        .open(new_challenge_filename)
        .expect("unable open challenge file in this directory");
    let new_challenge_readable_map = unsafe {
        MmapOptions::new()
            .map(&new_challenge_reader)
            .expect("unable to create a memory map for input")
    };

    let new_challenge_hash = calculate_hash(&new_challenge_readable_map);
    std::fs::File::create(new_challenge_hash_filename)
        .expect("unable to open new challenge hash file")
        .write_all(new_challenge_hash.as_slice())
        .expect("unable to write new challenge hash");

    parameters_before
        .verify(&parameters_after)
        .expect("should have successfully verified");
    info!(
        "Done!\n\n\
              The BLAKE2b hash of response file is:\n"
    );
    print_hash(&response_hash);
}
