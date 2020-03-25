use gumdrop::Options;
use phase2::chunked_groth16::contribute as chunked_contribute;
use rand::Rng;
use snark_utils::Result;
use std::fs::OpenOptions;
use zexe_algebra::SW6;

#[derive(Debug, Options, Clone)]
pub struct ContributeOpts {
    help: bool,
    #[options(
        help = "the previous contribution - the action will happen in place",
        default = "challenge"
    )]
    pub data: String,
    #[options(help = "the batches which can be loaded in memory", default = "50000")]
    pub batch: usize,
    #[options(
        help = "the beacon hash to be used if running a beacon contribution",
        default = "0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620"
    )]
    pub beacon_hash: String,
}

pub fn contribute<R: Rng>(opts: &ContributeOpts, rng: &mut R) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&opts.data)
        .expect("could not open file for writing the new MPC parameters ");

    chunked_contribute::<SW6, _, _>(&mut file, rng, opts.batch)?;

    Ok(())
}
