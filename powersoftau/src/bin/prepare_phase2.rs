use gumdrop::Options;
use powersoftau::{
    cli_common::{curve_from_str, proving_system_from_str, CurveKind, ProvingSystem},
    parameters::*,
    BatchedAccumulator,
};
use snark_utils::{Groth16Params, Result, UseCompression};

use zexe_algebra::{Bls12_377, PairingEngine};

use std::fs::OpenOptions;

use memmap::*;

#[derive(Debug, Options, Clone)]
struct PreparePhase2Opts {
    help: bool,
    #[options(
        help = "the file which will contain the FFT coefficients processed for Phase 2 of the setup"
    )]
    phase2_fname: String,
    #[options(
        help = "the response file which will be processed for the specialization (phase 2) of the setup"
    )]
    response_fname: String,
    #[options(
        help = "the elliptic curve to use",
        default = "bls12_377",
        parse(try_from_str = "curve_from_str")
    )]
    pub curve_kind: CurveKind,
    #[options(
        help = "the proving system to use",
        default = "groth16",
        parse(try_from_str = "proving_system_from_str")
    )]
    pub proving_system: ProvingSystem,
    #[options(help = "the size of batches to process", default = "256")]
    pub batch_size: usize,
    #[options(
        help = "the number of powers used for phase 1 (circuit size will be 2^{power})",
        default = "21"
    )]
    pub power: usize,
    #[options(help = "the size of the phase 2 circuit", default = "21")]
    pub phase2_size: usize,
}

fn main() -> Result<()> {
    let opts = PreparePhase2Opts::parse_args_default_or_exit();

    let parameters = CeremonyParams::<Bls12_377>::new(opts.power, opts.batch_size);

    prepare_phase2(
        &opts.response_fname,
        &opts.phase2_fname,
        &parameters,
        opts.phase2_size,
    )
}

fn prepare_phase2<E: PairingEngine + Sync>(
    response_filename: &str,
    phase2_filename: &str,
    parameters: &CeremonyParams<E>,
    phase2_size: usize,
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
    let current_accumulator =
        BatchedAccumulator::deserialize(&response_readable_map, UseCompression::Yes, &parameters)
            .expect("unable to read uncompressed accumulator");

    // Load the elements to the Groth16 utility
    let groth16_params = Groth16Params::<E>::new(
        phase2_size,
        current_accumulator.tau_powers_g1,
        current_accumulator.tau_powers_g2,
        current_accumulator.alpha_tau_powers_g1,
        current_accumulator.beta_tau_powers_g1,
        current_accumulator.beta_g2,
    );

    // Write the parameters
    groth16_params.write(&mut writer, UseCompression::No)?;

    Ok(())
}
