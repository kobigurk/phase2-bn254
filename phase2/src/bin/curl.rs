#![allow(unused_imports)]

extern crate reqwest;
extern crate phase2;
extern crate itertools;
extern crate blake2;
extern crate rand;
extern crate byteorder;

use std::io::Read;
use std::io::Write;
use std::fs::{File, OpenOptions};
use phase2::parameters::MPCParameters;
use itertools::Itertools;
use blake2::Digest;
use reqwest::blocking::multipart;
use std::time::Duration;

fn main() {
    let disallow_points_at_infinity = false;
    let entropy = "qweqwe";

    println!("Downloading challenge...");
    let mut resp = reqwest::blocking::get("https://trustedaf.poma.in/challenge").unwrap();
    if !resp.status().is_success() {
        println!("Cannot download challenge");
        std::process::exit(1);
    }
    let mut challenge: Vec<u8> = vec![];
    resp.copy_to(&mut challenge).unwrap();
    File::create("challenge").unwrap().write_all(&*challenge).unwrap();

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
    let mut params = MPCParameters::read(&*challenge, disallow_points_at_infinity, true).expect("unable to read params");

    println!("Contributing...");
    let hash = params.contribute(&mut rng);
    println!("Contribution hash: 0x{:02x}", hash.iter().format(""));

    println!("Sending parameters");
    let mut response: Vec<u8> = vec![];
    params.write(&mut response).expect("failed to write updated parameters");
    File::create("response").unwrap().write_all(&*response).unwrap();

    let part = multipart::Part::bytes(response).file_name("response").mime_str("application/octet-stream").unwrap();
    let client = reqwest::blocking::Client::new();
    let resp = client.post("https://trustedaf.poma.in/response")
        .multipart(multipart::Form::new().part("response", part))
        .timeout(Duration::from_secs(300))
        .send()
        .unwrap();

    if !resp.status().is_success() {
        println!("Cannot upload response");
        std::process::exit(1);
    }

    println!("Done");
}
