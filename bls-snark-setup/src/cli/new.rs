use gumdrop::Options;

use bls_snark::gadgets::ValidatorSetUpdate;
use zexe_algebra::{Bls12_377, SW6};
use zexe_r1cs_core::ConstraintSynthesizer;
use zexe_r1cs_std::test_constraint_counter::TestConstraintCounter;

use phase2::parameters::{circuit_to_qap, MPCParameters};
use snark_utils::{log_2, Groth16Params, Result, UseCompression};

use std::fs::OpenOptions;

#[derive(Debug, Options, Clone)]
pub struct NewOpts {
    help: bool,
    #[options(help = "the path to the phase1 parameters", default = "phase1")]
    pub phase1: String,
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

const COMPRESSION: UseCompression = UseCompression::Yes;

pub fn empty_circuit(opt: &NewOpts) -> (ValidatorSetUpdate<Bls12_377>, usize) {
    let maximum_non_signers = (opt.num_validators - 1) / 3;

    // Create an empty circuit
    let valset = ValidatorSetUpdate::empty(
        opt.num_validators,
        opt.num_epochs,
        maximum_non_signers,
        None, // The hashes are done over SW6 so no helper is provided for the setup
    );

    let num_constraints = {
        let mut counter = TestConstraintCounter::new();
        valset
            .clone()
            .generate_constraints(&mut counter)
            .expect("could not calculate number of required constraints");
        let constraints = counter.num_constraints();
        let power = log_2(constraints) as u32;
        // get the nearest power of 2
        if constraints < 2usize.pow(power) {
            2usize.pow(power + 1)
        } else {
            constraints
        }
    };

    (valset, num_constraints)
}

pub fn new(opt: &NewOpts) -> Result<()> {
    let mut phase1_transcript = OpenOptions::new()
        .read(true)
        .open(&opt.phase1)
        .expect("could not read phase 1 transcript file");
    let output = OpenOptions::new()
        .read(false)
        .write(true)
        .create_new(true)
        .open(&opt.output)
        .expect("could not open file for writing the MPC parameters ");

    let (valset, num_constraints) = empty_circuit(&opt);

    // Read `num_constraints` Lagrange coefficients from the Phase1 Powers of Tau which were
    // prepared for this step. This will fail if Phase 1 was too small.
    let phase1 = Groth16Params::<SW6>::read(&mut phase1_transcript, COMPRESSION, num_constraints)?;

    // Convert it to a QAP
    let keypair = circuit_to_qap(valset)?;

    // Generate the initial transcript
    let mpc = MPCParameters::new(keypair, phase1)?;
    mpc.write(output)?;

    Ok(())
}
