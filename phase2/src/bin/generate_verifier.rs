extern crate phase2;
extern crate exitcode;

use phase2::circom_circuit::{
    load_params_file,
    create_verifier_sol_file
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("Usage: \n<params> <out_contract.sol>");
        std::process::exit(exitcode::USAGE);
    }
    let params_filename = &args[1];
    let verifier_filename = &args[2];
    let params = load_params_file(params_filename);
    create_verifier_sol_file(&params, verifier_filename).unwrap();
    println!("Created {}", verifier_filename);
}