// Documentation
#![cfg_attr(nightly, feature(doc_cfg, external_doc))]
#![cfg_attr(nightly, doc(include = "../README.md"))]

mod combine;
pub use combine::combine;

mod contribute;
pub use contribute::contribute;

mod split;
pub use split::split;

mod new_challenge;
pub use new_challenge::new_challenge;

mod transform_pok_and_correctness;
pub use transform_pok_and_correctness::transform_pok_and_correctness;

mod transform_ratios;
pub use transform_ratios::transform_ratios;

use phase1::{
    helpers::{
        batch_exp_mode_from_str, contribution_mode_from_str, curve_from_str, proving_system_from_str, CurveKind,
    },
    ContributionMode, ProvingSystem,
};

use gumdrop::Options;
use setup_utils::BatchExpMode;
use std::default::Default;

#[derive(Debug, Options, Clone)]
pub struct Phase1Opts {
    help: bool,
    #[options(help = "the seed to derive private elements from")]
    pub seed: String,
    #[options(
        help = "the contribution mode",
        default = "chunked",
        parse(try_from_str = "contribution_mode_from_str")
    )]
    pub contribution_mode: ContributionMode,
    #[options(help = "the chunk index to process")]
    pub chunk_index: usize,
    #[options(help = "the chunk size")]
    pub chunk_size: usize,
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
    #[options(help = "the circuit power (circuit size will be 2^{power})", default = "21")]
    pub power: usize,
    #[options(command)]
    pub command: Option<Command>,
    #[options(
        help = "whether to always check whether incoming challenges are in correct subgroup and non-zero",
        default = "false"
    )]
    pub force_correctness_checks: bool,
    #[options(
        help = "which batch exponentiation version to use",
        default = "auto",
        parse(try_from_str = "batch_exp_mode_from_str")
    )]
    pub batch_exp_mode: BatchExpMode,
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
    #[options(help = "contribute randomness via a random beacon (e.g. a bitcoin block header hash)")]
    Beacon(ContributeOpts),
    // this receives a challenge + response file, verifies it and generates a new challenge, for a single chunk.
    #[options(help = "verify the contributions so far and generate a new challenge, for a single chunk")]
    VerifyAndTransformPokAndCorrectness(VerifyPokAndCorrectnessOpts),
    // this receives a challenge + response file, verifies it and generates a new challenge, for a full contribution.
    #[options(help = "verify the contributions so far and generate a new challenge, for a full contribution")]
    VerifyAndTransformRatios(VerifyRatiosOpts),
    // this receives a list of chunked responses and combines them into a single response.
    #[options(help = "receive a list of chunked responses and combines them into a single response")]
    Combine(CombineOpts),
    #[options(help = "receive a full contribution and splits it into chunks")]
    Split(SplitOpts),
}

// Options for the Contribute command
#[derive(Debug, Options, Clone)]
pub struct NewOpts {
    help: bool,
    #[options(help = "the challenge file name to be created", default = "challenge")]
    pub challenge_fname: String,
    #[options(help = "the new challenge file hash", default = "challenge.verified.hash")]
    pub challenge_hash_fname: String,
}

// Options for the Contribute command
#[derive(Debug, Options, Clone)]
pub struct ContributeOpts {
    help: bool,
    #[options(help = "the provided challenge file", default = "challenge")]
    pub challenge_fname: String,
    #[options(help = "the provided challenge file hash", default = "challenge.hash")]
    pub challenge_hash_fname: String,
    #[options(help = "the response file which will be generated")]
    pub response_fname: String,
    #[options(help = "the response file which will be generated hash", default = "response.hash")]
    pub response_hash_fname: String,
    #[options(
        help = "the beacon hash to be used if running a beacon contribution",
        default = "0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620"
    )]
    pub beacon_hash: String,
}

#[derive(Debug, Options, Clone)]
pub struct VerifyPokAndCorrectnessOpts {
    help: bool,
    #[options(help = "the provided challenge file", default = "challenge")]
    pub challenge_fname: String,
    #[options(help = "the provided challenge hash", default = "challenge.verified.hash")]
    pub challenge_hash_fname: String,
    #[options(help = "the provided response file which will be verified", default = "response")]
    pub response_fname: String,
    #[options(help = "the response file hash", default = "response.verified.hash")]
    pub response_hash_fname: String,
    #[options(
        help = "the new challenge file which will be generated in response",
        default = "new_challenge"
    )]
    pub new_challenge_fname: String,
    #[options(
        help = "the new challenge file which will be generated in response hash",
        default = "new_challenge.verified.hash"
    )]
    pub new_challenge_hash_fname: String,
}

#[derive(Debug, Options, Clone)]
pub struct VerifyRatiosOpts {
    help: bool,
    #[options(help = "the provided response file which will be verified", default = "response")]
    pub response_fname: String,
}

#[derive(Debug, Options, Clone)]
pub struct CombineOpts {
    help: bool,
    #[options(help = "the response files which will be combined", default = "response_list")]
    pub response_list_fname: String,
    #[options(help = "the combined response file", default = "combined")]
    pub combined_fname: String,
}

#[derive(Debug, Options, Clone)]
pub struct SplitOpts {
    help: bool,
    #[options(help = "the prefix for the chunked response files", default = "response")]
    pub chunk_fname_prefix: String,
    #[options(help = "the full response file", default = "full")]
    pub full_fname: String,
}
