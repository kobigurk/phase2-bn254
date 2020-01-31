extern crate phase2;
extern crate bellman_ce;
extern crate exitcode;
extern crate serde;
extern crate num_bigint;
extern crate num_traits;
extern crate itertools;

use std::fs;
use bellman_ce::pairing::bn256::Bn256;
use phase2::circom_circuit::{
    load_params_file,
    prove,
    verify,
    create_rng,
    proof_to_json_file,
    circuit_from_json_file,
    witness_from_json_file
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        println!("Usage: \n<circuit.json> <witness.json> <params> <proof.json> <public.json>");
        std::process::exit(exitcode::USAGE);
    }
    let circuit_filename = &args[1];
    let witness_filename = &args[2];
    let params_filename = &args[3];
    let proof_filename = &args[4];
    let public_filename = &args[5];

    let rng = create_rng();
    let params = load_params_file(params_filename);
    let mut circuit = circuit_from_json_file(circuit_filename);
    circuit.witness =  Some(witness_from_json_file::<Bn256>(witness_filename));

    println!("Proving...");
    let proof = prove(circuit.clone(), &params, rng).unwrap();

    println!("Verifying proof");
    let correct = verify(&circuit, &params, &proof).unwrap();
    assert!(correct, "Proof is correct");

    println!("Saving {} and {}", proof_filename, public_filename);
    proof_to_json_file(&proof, proof_filename).unwrap();
    fs::write(public_filename, circuit.get_public_inputs_json().as_bytes()).unwrap();

    println!("Done!")
}
