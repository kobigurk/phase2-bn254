// TODO: remove this.
#![allow(unused_variables)]
#![allow(unreachable_code)]
use phase2::parameters::MPCParameters;
use std::fs::File;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("Usage: \n<in_circuit.json> <out_params.params>");
        std::process::exit(exitcode::USAGE);
    }
    let circuit_filename = &args[1];
    let params_filename = &args[2];

    let should_filter_points_at_infinity = false;

    // Import the circuit and create the initial parameters using phase 1
    println!("Creating initial parameters for {}...", circuit_filename);
    // TODO: Figure out how to import the actual circuit.
    let params: MPCParameters = {
        // let c = unimplemented!();
        // MPCParameters::new(c, should_filter_points_at_infinity).unwrap()
        unimplemented!();
    };

    println!("Writing initial parameters to {}.", params_filename);
    let mut f = File::create(params_filename).unwrap();
    params.write(&mut f).expect("unable to write params");
}
