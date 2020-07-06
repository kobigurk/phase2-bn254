use powersoftau::{
    batched_accumulator::BatchedAccumulator,
    parameters::{CeremonyParams, CheckForCorrectness, UseCompression, ElementType},
};

use bellman_ce::pairing::bn256::Bn256;
use memmap::*;
use std::fs::OpenOptions;

const PREVIOUS_CHALLENGE_IS_COMPRESSED: UseCompression = UseCompression::No;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        println!("Usage: \n<challenge_file> <circuit_power> <batch_size> <category_to_extract> <num_to_extract>");
        std::process::exit(exitcode::USAGE);
    }
    let challenge_filename = &args[1];
    let circuit_power = args[2].parse().expect("could not parse circuit power");
    let batch_size = args[3].parse().expect("could not parse batch size");
    let element_type_to_extract: String = args[4].parse().expect("could not parse the element type of the value to extract");
    let num_to_extract = args[5].parse().expect("could not parse the number of values to extract");

    let parameters = CeremonyParams::<Bn256>::new(circuit_power, batch_size);

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

    let et = match String::from(element_type_to_extract.to_lowercase()).as_ref() {
        "taug1" => ElementType::TauG1,
        "taug2" => ElementType::TauG2,
        "alphag1" => ElementType::AlphaG1,
        "betag1" => ElementType::BetaG1,
        "betag2" => ElementType::BetaG2,
        _ => ElementType::TauG1,
    };

    BatchedAccumulator::print_powers(
        &challenge_readable_map,
        PREVIOUS_CHALLENGE_IS_COMPRESSED,
        CheckForCorrectness::No,
        &parameters,
        et,
        num_to_extract
    );
}
