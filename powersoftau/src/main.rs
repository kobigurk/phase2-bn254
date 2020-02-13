pub mod batched_accumulator;
mod cli_common;
pub mod keypair;
pub mod parameters;
pub mod utils;

use cli_common::{
    beacon, compute_constrained, new_constrained, transform, verify, Command, PowersOfTauOpts,
};
use gumdrop::Options;

use crate::parameters::CeremonyParams;
use bellman_ce::pairing::bn256::Bn256;
use std::path::PathBuf;
use std::process;

#[macro_use]
extern crate hex_literal;

fn main() {
    let opts: PowersOfTauOpts = PowersOfTauOpts::parse_args_default_or_exit();

    // TODO: Make this depend on `opts.curve_kind`
    let parameters = CeremonyParams::<Bn256>::new(opts.power, opts.batch_size);

    let command = opts.command.unwrap_or_else(|| {
        eprintln!("No command was provided.");
        eprintln!("{}", PowersOfTauOpts::usage());
        process::exit(2)
    });

    match command {
        Command::Contribute(opt) => {
            let challenge_fname = opt.challenge_fname;
            let challenge_file = PathBuf::from(&challenge_fname);

            if !challenge_file.exists() {
                // If the challenge file does not exist, then we have to first initiate the ceremony
                new_constrained(&challenge_fname, &parameters);
            }
            // contribute to the randomness
            compute_constrained(&challenge_fname, &opt.response_fname, &parameters)
        }
        Command::Beacon(opt) => {
            // use the beacon's randomness
            // Place block hash here (block number #564321)
            let beacon_hash: [u8; 32] =
                hex!("0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620");
            beacon(
                &opt.challenge_fname,
                &opt.response_fname,
                &parameters,
                beacon_hash,
            );
        }
        Command::Transform(opt) => {
            // we receive a previous participation, verify it, and generate a new challenge from it
            transform(
                &opt.challenge_fname,
                &opt.response_fname,
                &opt.new_challenge_fname,
                &parameters,
            );
        }
        Command::Verify(opt) => {
            verify(&opt.transcript_fname, &parameters);
        }
    };
}
