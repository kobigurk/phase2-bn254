mod new_challenge;
pub use new_challenge::new_challenge;

mod contribute;
pub use contribute::contribute;

mod transform;
pub use transform::transform;

use gumdrop::Options;
use std::default::Default;

#[derive(Debug, Clone)]
pub enum CurveKind {
    Bls12_381,
    Bls12_377,
    SW6,
}

#[derive(Debug, Clone)]
pub enum ProvingSystem {
    Groth16,
}

#[derive(Debug, Options, Clone)]
pub struct PowersOfTauOpts {
    help: bool,
    #[options(
        help = "the elliptic curve to use",
        default = "bls12_381",
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
        help = "the circuit power (circuit size will be 2^{power})",
        default = "21"
    )]
    pub power: usize,
    #[options(command)]
    pub command: Option<Command>,
}

// The supported commands
#[derive(Debug, Options, Clone)]
pub enum Command {
    // this creates a new challenge
    #[options(help = "creates a new challenge for the ceremony")]
    New(NewOpts),
    #[options(
        help = "contribute to ceremony by producing a response to a challenge (or create a new challenge if this is the first contribution)"
    )]
    Contribute(ContributeOpts),
    #[options(
        help = "contribute randomness via a random beacon (e.g. a bitcoin block header hash)"
    )]
    Beacon(ContributeOpts),
    // this receives a challenge + response file, verifies it and generates a new challenge
    #[options(help = "verify the contributions so far and generate a new challenge")]
    VerifyAndTransform(VerifyAndTransformOpts),
}

// Options for the Contribute command
#[derive(Debug, Options, Clone)]
pub struct NewOpts {
    help: bool,
    #[options(help = "the challenge file name to be created", default = "challenge")]
    pub challenge_fname: String,
}

// Options for the Contribute command
#[derive(Debug, Options, Clone)]
pub struct ContributeOpts {
    help: bool,
    #[options(help = "the provided challenge file", default = "challenge")]
    pub challenge_fname: String,
    #[options(help = "the response file which will be generated")]
    pub response_fname: String,
}

#[derive(Debug, Options, Clone)]
pub struct VerifyAndTransformOpts {
    help: bool,
    #[options(help = "the provided challenge file", default = "challenge")]
    pub challenge_fname: String,
    #[options(
        help = "the provided response file which will be verified",
        default = "response"
    )]
    pub response_fname: String,
    #[options(
        help = "the new challenge file which will be generated in response",
        default = "new_challenge"
    )]
    pub new_challenge_fname: String,
}

pub fn curve_from_str(src: &str) -> Result<CurveKind, String> {
    let curve = match src.to_lowercase().as_str() {
        "bls12_381" => CurveKind::Bls12_381,
        "bls12_377" => CurveKind::Bls12_377,
        "sw6" => CurveKind::SW6,
        _ => return Err("unsupported curve.".to_string()),
    };
    Ok(curve)
}

pub fn proving_system_from_str(src: &str) -> Result<ProvingSystem, String> {
    let system = match src.to_lowercase().as_str() {
        "groth16" => ProvingSystem::Groth16,
        _ => return Err("unsupported proving system. Currently supported: groth16".to_string()),
    };
    Ok(system)
}
