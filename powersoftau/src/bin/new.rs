use bellman_ce::pairing::bn256::Bn256;
use powersoftau::{
    accumulator::Accumulator,
    parameters::{CeremonyParams, CurveKind, UseCompression},
    utils::blank_hash,
};
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

    let parameters = CeremonyParams::new(
        CurveKind::Bn256,
        28, // turn this to 10 for the small test
        21, // turn this to 8  for the small test
    );

    let acc: Accumulator<Bn256> = Accumulator::new(&parameters);
    println!("Writing an empty accumulator to disk");
    acc.serialize(&mut writer, UseCompression::No)
        .expect("unable to write fresh accumulator to challenge file");
    writer.flush().expect("unable to flush accumulator to disk");

    println!("Wrote a fresh accumulator to challenge file");
}
