use phase1::{parameters::*, Phase1};
use setup_utils::{CheckForCorrectness, Groth16Params, Result, UseCompression};

use algebra::PairingEngine as Engine;

use memmap::*;
use std::fs::OpenOptions;

const INPUT_IS_COMPRESSED: UseCompression = UseCompression::No;
const OUTPUT_IS_COMPRESSED: UseCompression = UseCompression::No;

pub fn prepare_phase2<T: Engine + Sync>(
    phase2_filename: &str,
    response_filename: &str,
    num_powers: usize,
    parameters: &Phase1Parameters<T>,
) -> Result<()> {
    // Try to load response file from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open(response_filename)
        .expect("unable open response file in this directory");
    let response_readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    // Create the parameter file
    let mut writer = OpenOptions::new()
        .read(false)
        .write(true)
        .create_new(true)
        .open(phase2_filename)
        .expect("unable to create parameter file in this directory");

    // Deserialize the accumulator
    let current_accumulator = Phase1::deserialize(
        &response_readable_map,
        INPUT_IS_COMPRESSED,
        CheckForCorrectness::Full,
        &parameters,
    )
    .expect("unable to read uncompressed accumulator");

    // Load the elements to the Groth16 utility
    let groth16_params = Groth16Params::<T>::new(
        1 << num_powers,
        current_accumulator.tau_powers_g1,
        current_accumulator.tau_powers_g2,
        current_accumulator.alpha_tau_powers_g1,
        current_accumulator.beta_tau_powers_g1,
        current_accumulator.beta_g2,
    )
    .expect("could not create Groth16 Lagrange coefficients");

    // Write the parameters
    groth16_params.write(&mut writer, OUTPUT_IS_COMPRESSED)?;

    Ok(())
}
