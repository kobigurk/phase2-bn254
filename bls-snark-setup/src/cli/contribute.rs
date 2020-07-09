use gumdrop::Options;
use memmap::MmapOptions;
use phase2::{chunked_groth16::contribute as chunked_contribute, keypair::PublicKey};
use rand::Rng;
use snark_utils::Result;
use std::fs::OpenOptions;
use zexe_algebra::BW6_761;

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
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&opts.data)
        .expect("could not open file for writing the new MPC parameters ");
    let metadata = file.metadata()?;
    // extend the file by 1 pubkey
    file.set_len(metadata.len() + PublicKey::<BW6_761>::size() as u64)?;
    let mut file = unsafe {
        MmapOptions::new()
            .map_mut(&file)
            .expect("unable to create a memory map for input")
    };

    chunked_contribute::<BW6_761, _>(&mut file, rng, opts.batch)?;

    Ok(())
}
