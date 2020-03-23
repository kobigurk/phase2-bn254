use gumdrop::Options;

mod new;
pub use new::{empty_circuit, new, NewOpts};

mod contribute;
pub use contribute::{contribute, ContributeOpts};

mod verify;
pub use verify::{verify, VerifyOpts};

// The supported commands
#[derive(Debug, Options, Clone)]
pub enum Command {
    #[options(
        help = "prints the number of constraints required for the provided circuit parameters"
    )]
    Constraints(NewOpts),
    #[options(help = "creates new parameters for the ceremony which MUST be built upon")]
    New(NewOpts),
    #[options(help = "contribute to ceremony by transforming the circuit parameters")]
    Contribute(ContributeOpts),
    #[options(
        help = "contribute randomness via a random beacon (e.g. a bitcoin block header hash)"
    )]
    Beacon(ContributeOpts),
    #[options(help = "verify the contributions so far")]
    Verify(VerifyOpts),
}

#[derive(Debug, Options, Clone)]
pub struct SNARKOpts {
    help: bool,
    // #[options(help = "the size of batches to process", default = "256")]
    // pub batch_size: usize,
    #[options(command)]
    pub command: Option<Command>,
}
