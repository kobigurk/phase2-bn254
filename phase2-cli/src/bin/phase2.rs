use setup_utils::converters::CurveKind;

use algebra::{Bls12_377, PairingEngine as Engine, BW6_761};

use gumdrop::Options;
use phase2_cli::{combine, contribute, new_challenge, verify, Command, Phase2Opts};
use setup_utils::{
    derive_rng_from_seed, upgrade_correctness_check_config, CheckForCorrectness,
    DEFAULT_CONTRIBUTE_CHECK_INPUT_CORRECTNESS, DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
};
use std::fs::read_to_string;
use std::{process, time::Instant};
use tracing::{error, info};
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

fn execute_cmd<E: Engine>(opts: Phase2Opts) {
    let command = opts.clone().command.unwrap_or_else(|| {
        error!("No command was provided.");
        error!("{}", Phase2Opts::usage());
        process::exit(2)
    });

    let now = Instant::now();

    match command {
        Command::New(opt) => {
            new_challenge(
                &opt.challenge_fname,
                &opt.challenge_hash_fname,
                opts.chunk_size,
                &opt.phase1_fname,
                opt.phase1_powers,
                opt.num_validators,
                opt.num_epochs,
            );
        }
        Command::Contribute(opt) => {
            let seed = hex::decode(&read_to_string(&opts.seed).expect("should have read seed").trim())
                .expect("seed should be a hex string");
            let rng = derive_rng_from_seed(&seed);
            contribute(
                &opt.challenge_fname,
                &opt.challenge_hash_fname,
                &opt.response_fname,
                &opt.response_hash_fname,
                upgrade_correctness_check_config(
                    DEFAULT_CONTRIBUTE_CHECK_INPUT_CORRECTNESS,
                    opts.force_correctness_checks,
                ),
                opts.batch_exp_mode,
                rng,
            );
        }
        Command::Verify(opt) => {
            verify(
                &opt.challenge_fname,
                &opt.challenge_hash_fname,
                DEFAULT_VERIFY_CHECK_INPUT_CORRECTNESS,
                &opt.response_fname,
                &opt.response_hash_fname,
                CheckForCorrectness::OnlyNonZero,
                &opt.new_challenge_fname,
                &opt.new_challenge_hash_fname,
                opts.subgroup_check_mode,
            );
        }
        Command::Combine(opt) => {
            combine(
                &opt.initial_query_fname,
                &opt.initial_full_fname,
                &opt.response_list_fname,
                &opt.combined_fname,
            );
        }
    };

    let new_now = Instant::now();
    info!("Executing {:?} took: {:?}", opts, new_now.duration_since(now));
}

fn main() {
    Subscriber::builder()
        .with_target(false)
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let opts: Phase2Opts = Phase2Opts::parse_args_default_or_exit();

    match opts.curve_kind {
        CurveKind::Bls12_377 => execute_cmd::<Bls12_377>(opts),
        CurveKind::BW6 => execute_cmd::<BW6_761>(opts),
    };
}
