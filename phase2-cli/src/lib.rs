// Documentation
#![cfg_attr(nightly, feature(doc_cfg, external_doc))]
#![cfg_attr(nightly, doc(include = "../README.md"))]

mod new_challenge;
pub use new_challenge::new_challenge;

mod contribute;
pub use contribute::contribute;

mod verify;
pub use verify::verify;

mod combine;
pub use combine::combine;

use setup_utils::converters::{ContributionMode, CurveKind, ProvingSystem};

use gumdrop::Options;
use setup_utils::{
    converters::{
        batch_exp_mode_from_str, contribution_mode_from_str, curve_from_str, proving_system_from_str,
        subgroup_check_mode_from_str,
    },
    BatchExpMode, SubgroupCheckMode, UseCompression,
};
use std::default::Default;

pub const COMPRESS_CONTRIBUTE_INPUT: UseCompression = UseCompression::No;
pub const COMPRESS_CONTRIBUTE_OUTPUT: UseCompression = UseCompression::Yes;
pub const COMBINED_IS_COMPRESSED: UseCompression = UseCompression::No;

#[derive(Debug, Options, Clone)]
pub struct Phase2Opts {
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
    #[options(help = "the size of batches to process", default = "16384")]
    pub batch_size: usize,
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
    #[options(
        help = "which subgroup check version to use",
        default = "auto",
        parse(try_from_str = "subgroup_check_mode_from_str")
    )]
    pub subgroup_check_mode: SubgroupCheckMode,
}

// The supported commands
#[derive(Debug, Options, Clone)]
pub enum Command {
    // this creates a new challenge
    #[options(help = "creates a new challenge for the ceremony")]
    New(NewOpts),
    #[options(help = "contribute to ceremony by producing a response to a challenge")]
    Contribute(ContributeOpts),
    #[options(help = "verify the contributions so far and generate a new challenge, for a single chunk")]
    Verify(VerifyOpts),
    #[options(help = "combine the contributions and verify the final parameters")]
    Combine(CombineOpts),
}

// Options for the Contribute command
#[derive(Debug, Options, Clone)]
pub struct NewOpts {
    help: bool,
    #[options(help = "the challenge file name to be created", default = "challenge")]
    pub challenge_fname: String,
    #[options(help = "the new challenge file hash", default = "challenge.verified.hash")]
    pub challenge_hash_fname: String,
    #[options(help = "the list of challenge files", default = "new_challenge_list")]
    pub challenge_list_fname: String,
    #[options(help = "phase 1 file name", default = "phase1")]
    pub phase1_fname: String,
    #[options(help = "phase 1 powers")]
    pub phase1_powers: usize,
    #[options(help = "number of validators")]
    pub num_validators: usize,
    #[options(help = "number of epochs")]
    pub num_epochs: usize,
    #[options(help = "circuit file name", default = "circuit.constraints")]
    pub circuit_fname: String,
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
pub struct VerifyOpts {
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
        help = "the provided new challenge file which will be written to",
        default = "response"
    )]
    pub new_challenge_fname: String,
    #[options(help = "the new challenge file hash", default = "response.verified.hash")]
    pub new_challenge_hash_fname: String,
}

#[derive(Debug, Options, Clone)]
pub struct CombineOpts {
    help: bool,
    #[options(help = "the provided query initial file", default = "challenge")]
    pub initial_query_fname: String,
    #[options(help = "the provided full initial file", default = "challenge")]
    pub initial_full_fname: String,
    #[options(help = "the response files which will be combined", default = "response_list")]
    pub response_list_fname: String,
    #[options(help = "the combined response file", default = "combined")]
    pub combined_fname: String,
}
