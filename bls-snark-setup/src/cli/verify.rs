use gumdrop::Options;
use phase2::parameters::MPCParameters;
use snark_utils::Result;
use std::fs::OpenOptions;
use zexe_algebra::SW6;

// Options for the Contribute command
#[derive(Debug, Options, Clone)]
pub struct VerifyOpts {
    help: bool,
    #[options(help = "a previous contribution", default = "challenge")]
    pub before: String,
    #[options(help = "the current contribution", default = "challenge")]
    pub after: String,
}

pub fn verify(opts: &VerifyOpts) -> Result<()> {
    let mut before = OpenOptions::new()
        .read(true)
        .open(&opts.before)
        .expect("could not read the previous participant's MPC transcript file");
    let before = MPCParameters::<SW6>::read(&mut before)?;

    let mut after = OpenOptions::new()
        .read(true)
        .open(&opts.after)
        .expect("could not read the previous participant's MPC transcript file");
    let after = MPCParameters::<SW6>::read(&mut after)?;

    before.verify(&after)?;

    Ok(())
}
