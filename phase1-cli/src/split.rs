use phase1::{Phase1, Phase1Parameters, ProvingSystem};
use setup_utils::UseCompression;

use zexe_algebra::PairingEngine as Engine;

use memmap::*;
use std::fs::OpenOptions;

const CONTRIBUTION_IS_COMPRESSED: UseCompression = UseCompression::Yes;
const COMPRESS_NEW_SPLIT: UseCompression = UseCompression::No;

pub fn split<T: Engine + Sync>(chunk_filename_prefix: &str, combined_filename: &str, parameters: &Phase1Parameters<T>) {
    println!("Will split contributions");

    let mut writers = vec![];

    let powers_length = 1 << parameters.total_size_in_log2;
    let powers_g1_length = (powers_length << 1) - 1;
    let powers_length_for_proving_system = match parameters.proving_system {
        ProvingSystem::Groth16 => powers_g1_length,
        ProvingSystem::Marlin => powers_length,
    };
    let num_chunks = (powers_length_for_proving_system + parameters.chunk_size - 1) / parameters.chunk_size;

    for chunk_index in 0..num_chunks {
        let parameters =
            parameters.into_chunk_parameters(parameters.contribution_mode, chunk_index, parameters.chunk_size);
        let response_writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(format!("{}_{}", chunk_filename_prefix, chunk_index))
            .expect("unable open response file in this directory");

        response_writer
            .set_len(parameters.accumulator_size as u64)
            .expect("must make output file large enough");

        unsafe {
            writers.push(
                MmapOptions::new()
                    .map_mut(&response_writer)
                    .expect("should have mapped the writer"),
            );
        }
    }

    let reader = OpenOptions::new()
        .read(true)
        .open(combined_filename)
        .expect("unable to read full file");

    let mut readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    {
        let parameters_for_input = Phase1Parameters::<T>::new(
            parameters.contribution_mode,
            0,
            parameters.powers_g1_length,
            parameters.curve.clone(),
            parameters.proving_system,
            parameters.total_size_in_log2,
            parameters.batch_size,
        );
        let metadata = reader
            .metadata()
            .expect("unable to get filesystem metadata for response file");
        let expected_response_length = match CONTRIBUTION_IS_COMPRESSED {
            UseCompression::Yes => parameters_for_input.contribution_size,
            UseCompression::No => parameters_for_input.accumulator_size,
        };
        if metadata.len() != (expected_response_length as u64) {
            panic!(
                "The size of response file should be {}, but it's {}, so something isn't right.",
                expected_response_length,
                metadata.len()
            );
        }
    }

    let parameters = Phase1Parameters::<T>::new(
        parameters.contribution_mode,
        0,
        parameters.chunk_size,
        parameters.curve.clone(),
        parameters.proving_system,
        parameters.total_size_in_log2,
        parameters.batch_size,
    );
    let res = Phase1::split(
        (&mut readable_map, CONTRIBUTION_IS_COMPRESSED),
        writers
            .iter_mut()
            .map(|r| (r.as_mut(), COMPRESS_NEW_SPLIT))
            .collect::<Vec<_>>(),
        &parameters,
    );

    if let Err(e) = res {
        println!("Splitting failed: {}", e);
        panic!("INVALID CONTRIBUTIONS!!!");
    } else {
        println!("Splitting succeeded!");
    }
}
