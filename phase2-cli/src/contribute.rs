use phase2::parameters::MPCParameters;
use setup_utils::{calculate_hash, print_hash, BatchExpMode, CheckForCorrectness, SubgroupCheckMode};

use algebra::BW6_761;

use crate::{COMPRESS_CONTRIBUTE_INPUT, COMPRESS_CONTRIBUTE_OUTPUT};
use rand::Rng;
use std::io::Write;
use tracing::info;

pub fn contribute(
    challenge_filename: &str,
    challenge_hash_filename: &str,
    response_filename: &str,
    response_hash_filename: &str,
    check_input_correctness: CheckForCorrectness,
    batch_exp_mode: BatchExpMode,
    mut rng: impl Rng,
) {
    info!("Contributing to phase 2");

    let challenge_contents = std::fs::read(challenge_filename).expect("should have read challenge");
    let challenge_hash = calculate_hash(&challenge_contents);
    std::fs::File::create(challenge_hash_filename)
        .expect("unable to open current accumulator hash file")
        .write_all(&challenge_hash)
        .expect("unable to write current accumulator hash");

    info!("`challenge` file contains decompressed points and has a hash:");
    print_hash(&challenge_hash);

    let mut parameters = MPCParameters::<BW6_761>::read_fast(
        challenge_contents.as_slice(),
        COMPRESS_CONTRIBUTE_INPUT,
        check_input_correctness,
        false,
        SubgroupCheckMode::Auto,
    )
    .expect("should have read parameters");
    parameters
        .contribute(batch_exp_mode, &mut rng)
        .expect("should have successfully contributed");
    let mut serialized_response = vec![];
    parameters
        .write(&mut serialized_response, COMPRESS_CONTRIBUTE_OUTPUT)
        .expect("should have written input");
    std::fs::File::create(response_filename)
        .expect("unable to create response")
        .write_all(&serialized_response)
        .expect("unable to write the response");
    let response_hash = calculate_hash(&serialized_response);
    std::fs::File::create(response_hash_filename)
        .expect("unable to create response hash")
        .write_all(&response_hash)
        .expect("unable to write the response hash");
    info!(
        "Done!\n\n\
              Your contribution has been written to response file\n\n\
              The BLAKE2b hash of response file is:\n"
    );
    print_hash(&response_hash);
}
