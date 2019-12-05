extern crate rand;
extern crate phase2;
extern crate memmap;
extern crate num_bigint;
extern crate num_traits;
extern crate blake2;
extern crate byteorder;
extern crate exitcode;
extern crate itertools;
extern crate crypto;

use itertools::Itertools;

use std::fs::File;
use std::fs::OpenOptions;

#[macro_use]
extern crate hex_literal;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("Usage: \n<in_params.params> <out_params.params>");
        std::process::exit(exitcode::USAGE);
    }
    let in_params_filename = &args[1];
    let out_params_filename = &args[2];

    // Create an RNG based on the outcome of the random beacon
    let mut rng = {
        use byteorder::{ReadBytesExt, BigEndian};
        use rand::{SeedableRng};
        use rand::chacha::ChaChaRng;
        use crypto::sha2::Sha256;
        use crypto::digest::Digest;

        // Place block hash here (block number #564321)
        let mut cur_hash: [u8; 32] = hex!("0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620");

        // Performs 2^n hash iterations over it
        const N: usize = 10;

        for i in 0..(1u64<<N) {
            // Print 1024 of the interstitial states
            // so that verification can be
            // parallelized

            if i % (1u64<<(N-10)) == 0 {
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
        println!("");

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
    let mut params = phase2::MPCParameters::read(reader, true).expect("unable to read params");

    println!("Contributing to {}...", in_params_filename);
    let hash = params.contribute(&mut rng);
    println!("Contribution hash: 0x{:02x}", hash.iter().format(""));

    println!("Writing parameters to {}.", out_params_filename);
    let mut f = File::create(out_params_filename).unwrap();
    params.write(&mut f).expect("failed to write updated parameters");
}
