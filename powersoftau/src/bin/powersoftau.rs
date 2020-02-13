use gumdrop::Options;
use powersoftau::cli_common::{
    contribute, new_constrained, transform, verify, Command, PowersOfTauOpts,
};
use powersoftau::parameters::CeremonyParams;
use powersoftau::utils::{beacon_randomness, get_rng, user_system_randomness};

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
            let rng = get_rng(&user_system_randomness());
            contribute(&challenge_fname, &opt.response_fname, &parameters, rng)
        }
        Command::Beacon(opt) => {
            // use the beacon's randomness
            // Place block hash here (block number #564321)
            let beacon_hash: [u8; 32] =
                hex!("0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620");
            let rng = get_rng(&beacon_randomness(beacon_hash));
            contribute(&opt.challenge_fname, &opt.response_fname, &parameters, rng);
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
