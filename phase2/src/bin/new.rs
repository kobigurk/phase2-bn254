extern crate rand;
extern crate phase2;
extern crate exitcode;

use std::fs::File;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("Usage: \n<in_circuit.json> <out_params.params>");
        std::process::exit(exitcode::USAGE);
    }
    let circuit_filename = &args[1];
    let params_filename = &args[2];

    // Import the circuit and create the initial parameters using phase 1
    println!("Creating initial parameters for {}...", circuit_filename);
    let should_filter_points_at_infinity = false;
    let params = {
        let c = phase2::CircomCircuit {
            file_name: &circuit_filename,
        };
        phase2::MPCParameters::new(c, should_filter_points_at_infinity).unwrap()
    };

    println!("Writing initial parameters to {}.", params_filename);
    let mut f = File::create(params_filename).unwrap();
    params.write(&mut f).expect("unable to write params");
}
