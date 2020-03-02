use powersoftau::{
    batched_accumulator::BatchedAccumulator,
    keypair::*,
    parameters::{CeremonyParams, CheckForCorrectness},
};
use rand::thread_rng;
use snark_utils::*;
use zexe_algebra::PairingEngine;

use powersoftau_v1::parameters::UseCompression as UseCompressionV1;
use snark_utils::UseCompression;

// Unfortunately we need to convert datatypes from the current version
// to be compatible to the imported version
pub fn compat(compression: UseCompression) -> UseCompressionV1 {
    match compression {
        UseCompression::Yes => UseCompressionV1::Yes,
        UseCompression::No => UseCompressionV1::No,
    }
}

// helper for testing verification of a transformation
// it creates an initial accumulator and contributes to it
// the test must call verify on the returned values
pub fn setup_verify<E: PairingEngine>(
    compressed_input: UseCompression,
    compressed_output: UseCompression,
    parameters: &CeremonyParams<E>,
) -> (Vec<u8>, Vec<u8>, PublicKey<E>, GenericArray<u8, U64>) {
    let (input, _) = generate_input(&parameters, compressed_input);
    let mut output = generate_output(&parameters, compressed_output);

    // Construct our keypair
    let current_accumulator_hash = blank_hash();
    let mut rng = thread_rng();
    let (pubkey, privkey) =
        keypair(&mut rng, current_accumulator_hash.as_ref()).expect("could not generate keypair");

    // transform the accumulator
    BatchedAccumulator::contribute(
        &input,
        &mut output,
        compressed_input,
        compressed_output,
        CheckForCorrectness::No,
        &privkey,
        parameters,
    )
    .unwrap();
    // ensure that the key is not available to the verifier
    drop(privkey);

    (input, output, pubkey, current_accumulator_hash)
}

pub fn generate_input<E: PairingEngine>(
    parameters: &CeremonyParams<E>,
    compressed: UseCompression,
) -> (Vec<u8>, BatchedAccumulator<E>) {
    let len = parameters.get_length(compressed);
    let mut output = vec![0; len];
    BatchedAccumulator::generate_initial(&mut output, compressed, &parameters).unwrap();
    let mut input = vec![0; len];
    input.copy_from_slice(&output);
    let before =
        BatchedAccumulator::deserialize(&output, CheckForCorrectness::Yes, compressed, &parameters)
            .unwrap();
    (input, before)
}

pub fn generate_output<E: PairingEngine>(
    parameters: &CeremonyParams<E>,
    compressed: UseCompression,
) -> Vec<u8> {
    let expected_response_length = parameters.get_length(compressed);
    vec![0; expected_response_length]
}
