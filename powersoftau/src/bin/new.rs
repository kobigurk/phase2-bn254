use powersoftau::accumulator::Accumulator;
use powersoftau::bn256::Bn256CeremonyParameters;
use powersoftau::parameters::UseCompression;
use powersoftau::utils::blank_hash;

use bellman_ce::pairing::bn256::Bn256;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: \n<challenge_file>");
        std::process::exit(exitcode::USAGE);
    }
    let challenge_filename = &args[1];

    let file = OpenOptions::new()
        .read(false)
        .write(true)
        .create_new(true)
        .open(challenge_filename)
        .expect("unable to create challenge file");

    let mut writer = BufWriter::new(file);

    // Write a blank BLAKE2b hash:
    writer
        .write_all(&blank_hash().as_slice())
        .expect("unable to write blank hash to challenge file");

    let parameters = Bn256CeremonyParameters {};

    let acc: Accumulator<Bn256, _> = Accumulator::new(parameters);
    println!("Writing an empty accumulator to disk");
    acc.serialize(&mut writer, UseCompression::No)
        .expect("unable to write fresh accumulator to challenge file");
    writer.flush().expect("unable to flush accumulator to disk");

    println!("Wrote a fresh accumulator to challenge file");
}
