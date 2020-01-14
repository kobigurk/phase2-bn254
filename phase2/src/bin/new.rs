extern crate rand;
extern crate phase2;
extern crate exitcode;

use std::fs::File;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        println!("Usage: \n<in_circuit.json> <out_params.params> <path/to/phase1radix>");
        std::process::exit(exitcode::USAGE);
    }
    let circuit_filename = &args[1];
    let params_filename = &args[2];
    let radix_directory = &args[3];

    let should_filter_points_at_infinity = false;

    // Import the circuit and create the initial parameters using phase 1
    println!("Creating initial parameters for {}...", circuit_filename);
    println!("creating");
    let params = {
        let c = phase2::CircomCircuit {
            file_name: &circuit_filename,
        };
        phase2::MPCParameters::new(c, should_filter_points_at_infinity, radix_directory).unwrap()
    };

    println!("Writing initial parameters to {}.", params_filename);
    let mut f = File::create(params_filename).unwrap();
    params.write(&mut f).expect("unable to write params");
    println!("wrote");
}
