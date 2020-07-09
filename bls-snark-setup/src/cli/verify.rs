use gumdrop::Options;
use memmap::MmapOptions;
use phase2::chunked_groth16::verify as chunked_verify;
use snark_utils::Result;
use std::fs::OpenOptions;
use zexe_algebra::BW6_761;

// Options for the Contribute command
#[derive(Debug, Options, Clone)]
pub struct VerifyOpts {
    help: bool,
    #[options(help = "a previous contribution", default = "challenge")]
    pub before: String,
    #[options(help = "the current contribution", default = "challenge")]
    pub after: String,
    #[options(help = "the batches which can be loaded in memory", default = "50000")]
    pub batch: usize,
}

pub fn verify(opts: &VerifyOpts) -> Result<()> {
    let before = OpenOptions::new()
        .read(true)
        .open(&opts.before)
        .expect("could not read the previous participant's MPC transcript file");
    let mut before = unsafe {
        MmapOptions::new()
            .map_mut(&before)
            .expect("unable to create a memory map for input")
    };
    let after = OpenOptions::new()
        .read(true)
        .open(&opts.after)
        .expect("could not read the previous participant's MPC transcript file");
    let mut after = unsafe {
        MmapOptions::new()
            .map_mut(&after)
            .expect("unable to create a memory map for input")
    };
    chunked_verify::<BW6_761>(&mut before, &mut after, opts.batch)?;
    Ok(())
}
