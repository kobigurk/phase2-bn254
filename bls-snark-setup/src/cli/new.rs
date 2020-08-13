use gumdrop::Options;

use bls_snark::ValidatorSetUpdate;
use zexe_algebra::{Bls12_377, BW6_761};
use zexe_r1cs_core::ConstraintSynthesizer;
use zexe_r1cs_std::test_constraint_counter::ConstraintCounter;

use phase2::parameters::{circuit_to_qap, MPCParameters};
use snark_utils::{log_2, Groth16Params, Result, UseCompression};

use memmap::MmapOptions;
use std::fs::OpenOptions;

#[derive(Debug, Options, Clone)]
pub struct NewOpts {
    help: bool,
    #[options(help = "the path to the phase1 parameters", default = "phase1")]
    pub phase1: String,
    #[options(
        help = "the total number of coefficients (in powers of 2) which were created after processing phase 1"
    )]
    pub phase1_size: u32,
    #[options(help = "the challenge file name to be created", default = "challenge")]
    pub output: String,
    #[options(
        help = "the number of epochs the snark will prove",
        default = "180" // 6 months
    )]
    pub num_epochs: usize,
    #[options(
        help = "the number of validators the snark will support",
        default = "100"
    )]
    pub num_validators: usize,
}

const COMPRESSION: UseCompression = UseCompression::No;

pub fn empty_circuit(opt: &NewOpts) -> (ValidatorSetUpdate<Bls12_377>, usize) {
    let maximum_non_signers = (opt.num_validators - 1) / 3;

    // Create an empty circuit
    let valset = ValidatorSetUpdate::empty(
        opt.num_validators,
        opt.num_epochs,
        maximum_non_signers,
        None, // The hashes are done over BW6 so no helper is provided for the setup
    );

    let phase2_size = {
        let mut counter = ConstraintCounter::new();
        valset
            .clone()
            .generate_constraints(&mut counter)
            .expect("could not calculate number of required constraints");
        let phase2_size = std::cmp::max(
            counter.num_constraints,
            counter.num_aux + counter.num_inputs + 1,
        );
        let power = log_2(phase2_size) as u32;
        // get the nearest power of 2
        if phase2_size < 2usize.pow(power) {
            2usize.pow(power + 1)
        } else {
            phase2_size
        }
    };

    (valset, phase2_size)
}

pub fn new(opt: &NewOpts) -> Result<()> {
    let phase1_transcript = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&opt.phase1)
        .expect("could not read phase 1 transcript file");
    let mut phase1_transcript = unsafe {
        MmapOptions::new()
            .map_mut(&phase1_transcript)
            .expect("unable to create a memory map for input")
    };
    let mut output = OpenOptions::new()
        .read(false)
        .write(true)
        .create_new(true)
        .open(&opt.output)
        .expect("could not open file for writing the MPC parameters ");

    let (valset, phase2_size) = empty_circuit(&opt);

    // Read `num_constraints` Lagrange coefficients from the Phase1 Powers of Tau which were
    // prepared for this step. This will fail if Phase 1 was too small.
    let phase1 = Groth16Params::<BW6_761>::read(
        &mut phase1_transcript,
        COMPRESSION,
        2usize.pow(opt.phase1_size),
        phase2_size,
    )?;

    // Convert it to a QAP
    let keypair = circuit_to_qap(valset)?;

    // Generate the initial transcript
    let mpc = MPCParameters::new(keypair, phase1)?;
    mpc.write(&mut output)?;

    Ok(())
}
