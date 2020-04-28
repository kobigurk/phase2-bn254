extern crate rand;
extern crate phase2;
extern crate exitcode;
extern crate zkutil;

use std::fs::File;
use phase2::parameters::MPCParameters;
use zkutil::circom_circuit::{
    CircomCircuit,
    r1cs_from_json_file,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        println!("Usage: \n<in_circuit.json> <out_params.params> <path/to/phase1radix>");
        std::process::exit(exitcode::USAGE);
    }
    let circuit_filename = &args[1];
    let params_filename = &args[2];
    let radix_directory = &args[3];

    // Import the circuit and create the initial parameters using phase 1
    println!("Creating initial parameters for {}...", circuit_filename);
    let params = {
        let c = CircomCircuit {
            r1cs: r1cs_from_json_file(&circuit_filename),
            witness: None,
        };
        MPCParameters::new(c, radix_directory).unwrap()
    };

    println!("Writing initial parameters to {}.", params_filename);
    let mut f = File::create(params_filename).unwrap();
    params.write(&mut f).expect("unable to write params");
}
