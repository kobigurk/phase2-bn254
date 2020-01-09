extern crate rand;
extern crate phase2;
extern crate num_bigint;
extern crate num_traits;
extern crate blake2;
extern crate byteorder;
extern crate exitcode;
extern crate itertools;

use itertools::Itertools;

use std::fs::File;
use std::fs::OpenOptions;

use phase2::parameters::MPCParameters;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        println!("Usage: \n<in_params.params> <out_params.params> <in_str_entropy>");
        std::process::exit(exitcode::USAGE);
    }
    let in_params_filename = &args[1];
    let out_params_filename = &args[2];
    let entropy = &args[3];

    let disallow_points_at_infinity = false;

    // Create an RNG based on a mixture of system randomness and user provided randomness
    let mut rng = {
        use byteorder::{ReadBytesExt, BigEndian};
        use blake2::{Blake2b, Digest};
        use rand::{SeedableRng, Rng, OsRng};
        use rand::chacha::ChaChaRng;

        let h = {
            let mut system_rng = OsRng::new().unwrap();
            let mut h = Blake2b::default();

            // Gather 1024 bytes of entropy from the system
            for _ in 0..1024 {
                let r: u8 = system_rng.gen();
                h.input(&[r]);
            }

            // Hash it all up to make a seed
            h.input(&entropy.as_bytes());
            h.result()
        };

        let mut digest = &h[..];

        // Interpret the first 32 bytes of the digest as 8 32-bit words
        let mut seed = [0u32; 8];
        for i in 0..8 {
            seed[i] = digest.read_u32::<BigEndian>().expect("digest is large enough for this to work");
        }

        ChaChaRng::from_seed(&seed)
    };

    let reader = OpenOptions::new()
                            .read(true)
                            .open(in_params_filename)
                            .expect("unable to open.");
    let mut params = MPCParameters::read(reader, disallow_points_at_infinity, true).expect("unable to read params");

    println!("Contributing to {}...", in_params_filename);
    let hash = params.contribute(&mut rng);
    println!("Contribution hash: 0x{:02x}", hash.iter().format(""));

    println!("Writing parameters to {}.", out_params_filename);
    let mut f = File::create(out_params_filename).unwrap();
    params.write(&mut f).expect("failed to write updated parameters");
}
