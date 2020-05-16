extern crate phase2;
extern crate exitcode;
extern crate zkutil;

use std::fs::OpenOptions;

use phase2::parameters::*;
use zkutil::circom_circuit::{
    CircomCircuit,
    r1cs_from_json_file,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        println!("Usage: \n<in_circuit.json> <in_old_params.params> <in_new_params.params> <path/to/phase1radix>");
        std::process::exit(exitcode::USAGE);
    }
    let circuit_filename = &args[1];
    let old_params_filename = &args[2];
    let new_params_filename = &args[3];
    let radix_directory = &args[4];

    let old_reader = OpenOptions::new()
                                .read(true)
                                .open(old_params_filename)
                                .expect("unable to open old params");
    let old_params = MPCParameters::read(old_reader, true).expect("unable to read old params");

    let new_reader = OpenOptions::new()
                                .read(true)
                                .open(new_params_filename)
                                .expect("unable to open new params");
    let new_params = MPCParameters::read(new_reader, true).expect("unable to read new params");

    println!("Checking contribution {}...", new_params_filename);
    let contribution = verify_contribution(&old_params, &new_params).expect("should verify");

    let c = CircomCircuit {
        r1cs: r1cs_from_json_file(&circuit_filename),
        witness: None,
    };
    let verification_result = new_params.verify(c, radix_directory).unwrap();
    assert!(contains_contribution(&verification_result, &contribution));
    println!("Contribution {} verified.", new_params_filename);
}
