use phase1::parameters::*;
use phase1_cli::prepare_phase2;
use setup_utils::converters::{curve_from_str, proving_system_from_str, CurveKind, ProvingSystem};
use setup_utils::Result;

use algebra::{Bls12_377, BW6_761};

use gumdrop::Options;
use std::time::Instant;
use tracing::info;
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

#[derive(Debug, Options, Clone)]
struct PreparePhase2Opts {
    help: bool,
    #[options(help = "the file which will contain the FFT coefficients processed for Phase 2 of the setup")]
    phase2_fname: String,
    #[options(help = "the response file which will be processed for the specialization (phase 2) of the setup")]
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
    #[options(help = "the number of powers used for phase 1 (circuit size will be 2^{power})")]
    pub power: usize,
}

fn main() -> Result<()> {
    Subscriber::builder()
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let opts = PreparePhase2Opts::parse_args_default_or_exit();

    let now = Instant::now();
    match opts.curve_kind {
        CurveKind::Bls12_377 => {
            let parameters = Phase1Parameters::<Bls12_377>::new_full(opts.proving_system, opts.power, opts.batch_size);
            prepare_phase2::<Bls12_377>(&opts.phase2_fname, &opts.response_fname, opts.power, &parameters)?
        }
        CurveKind::BW6 => {
            let parameters = Phase1Parameters::<BW6_761>::new_full(opts.proving_system, opts.power, opts.batch_size);
            prepare_phase2::<BW6_761>(&opts.phase2_fname, &opts.response_fname, opts.power, &parameters)?
        }
    }

    let new_now = Instant::now();
    info!("Executing {:?} took: {:?}", opts, new_now.duration_since(now));

    Ok(())
}
