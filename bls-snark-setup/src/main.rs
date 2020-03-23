use snark_utils::{beacon_randomness, from_slice, get_rng, user_system_randomness};

use gumdrop::Options;
use std::{process, time::Instant};

mod cli;
use cli::*;

fn main() {
    let opts = SNARKOpts::parse_args_default_or_exit();

    let command = opts.clone().command.unwrap_or_else(|| {
        eprintln!("No command was provided.");
        eprintln!("{}", SNARKOpts::usage());
        process::exit(2)
    });

    let now = Instant::now();
    let res = match command {
        Command::Constraints(ref opt) => {
            println!("Circuit requires {} constraints", empty_circuit(&opt).1);
            Ok(())
        }
        Command::New(ref opt) => new(&opt),
        Command::Contribute(ref opt) => {
            // contribute to the randomness
            let mut rng = get_rng(&user_system_randomness());
            contribute(&opt, &mut rng)
        }
        Command::Beacon(ref opt) => {
            // use the beacon's randomness
            let beacon_hash =
                hex::decode(&opt.beacon_hash).expect("could not hex decode beacon hash");
            let mut rng = get_rng(&beacon_randomness(from_slice(&beacon_hash)));
            contribute(&opt, &mut rng)
        }
        Command::Verify(ref opt) => verify(&opt),
    };

    let new_now = Instant::now();
    println!(
        "Executing {:?} took: {:?}. Result {:?}",
        opts,
        new_now.duration_since(now),
        res,
    );
}
