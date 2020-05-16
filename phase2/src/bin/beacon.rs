extern crate rand;
extern crate phase2;
extern crate num_bigint;
extern crate num_traits;
extern crate blake2;
extern crate byteorder;
extern crate exitcode;
extern crate itertools;
extern crate crypto;
extern crate hex;

use itertools::Itertools;

use std::fs::File;
use std::fs::OpenOptions;

use phase2::parameters::MPCParameters;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        println!("Usage: \n<in_params.params> <in_beacon_hash> <in_num_iterations_exp> <out_params.params>");
        std::process::exit(exitcode::USAGE);
    }
    let in_params_filename = &args[1];
    let beacon_hash = &args[2];
    let num_iterations_exp = &args[3].parse::<usize>().unwrap();
    let out_params_filename = &args[4];

    if *num_iterations_exp < 10 || *num_iterations_exp > 63 {
        println!("in_num_iterations_exp should be in [10, 63] range");
        std::process::exit(exitcode::DATAERR);
    }

    // Create an RNG based on the outcome of the random beacon
    let mut rng = {
        use byteorder::{ReadBytesExt, BigEndian};
        use rand::{SeedableRng};
        use rand::chacha::ChaChaRng;
        use crypto::sha2::Sha256;
        use crypto::digest::Digest;

        // The hash used for the beacon
        let hash_result = hex::decode(beacon_hash);
        if hash_result.is_err() {
            println!("Beacon hash should be in hexadecimal format");
            std::process::exit(exitcode::DATAERR);
        }
        let mut cur_hash = hash_result.unwrap();
        if cur_hash.len() != 32 {
            println!("Beacon hash should be 32 bytes long");
            std::process::exit(exitcode::DATAERR);
        }
        // Performs 2^n hash iterations over it
        let n: usize = *num_iterations_exp;

        for i in 0..(1u64<<n) {
            // Print 1024 of the interstitial states
            // so that verification can be
            // parallelized

            if i % (1u64<<(n-10)) == 0 {
                print!("{}: ", i);
                for b in cur_hash.iter() {
                    print!("{:02x}", b);
                }
                println!("");
            }

            let mut h = Sha256::new();
            h.input(&cur_hash);
            h.result(&mut cur_hash);
        }

        print!("Final result of beacon: ");
        for b in cur_hash.iter() {
            print!("{:02x}", b);
        }
        println!();

        let mut digest = &cur_hash[..];

        let mut seed = [0u32; 8];
        for i in 0..8 {
            seed[i] = digest.read_u32::<BigEndian>().expect("digest is large enough for this to work");
        }

        ChaChaRng::from_seed(&seed)
    };

    println!("Done creating a beacon RNG");

    let reader = OpenOptions::new()
                            .read(true)
                            .open(in_params_filename)
                            .expect("unable to open.");
    let mut params = MPCParameters::read(reader, true).expect("unable to read params");

    println!("Contributing to {}...", in_params_filename);
    let zero: u32 = 0;
    let hash = params.contribute(&mut rng, &zero);
    println!("Contribution hash: 0x{:02x}", hash.iter().format(""));

    println!("Writing parameters to {}.", out_params_filename);
    let mut f = File::create(out_params_filename).unwrap();
    params.write(&mut f).expect("failed to write updated parameters");
}
