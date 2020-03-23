use gumdrop::Options;
use phase2::parameters::MPCParameters;
use rand::Rng;
use snark_utils::Result;
use std::fs::OpenOptions;
use zexe_algebra::SW6;

#[derive(Debug, Options, Clone)]
pub struct ContributeOpts {
    help: bool,
    #[options(help = "the previous contribution", default = "challenge")]
    pub input: String,
    #[options(help = "the new file after your contribution", default = "challenge")]
    pub output: String,
    #[options(
        help = "the beacon hash to be used if running a beacon contribution",
        default = "0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620"
    )]
    pub beacon_hash: String,
}

pub fn contribute<R: Rng>(opts: &ContributeOpts, rng: &mut R) -> Result<()> {
    let mut mpc_transcript = OpenOptions::new()
        .read(true)
        .open(&opts.input)
        .expect("could not read the MPC transcript file");
    let output = OpenOptions::new()
        .read(false)
        .write(true)
        .create_new(true)
        .open(&opts.output)
        .expect("could not open file for writing the new MPC parameters ");

    let mut mpc = MPCParameters::<SW6>::read(&mut mpc_transcript)?;
    mpc.contribute(rng)?;
    mpc.write(output)?;

    Ok(())
}
