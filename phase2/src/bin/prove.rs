extern crate phase2;
extern crate bellman_ce;
extern crate exitcode;
extern crate serde;
extern crate num_bigint;
extern crate num_traits;

use std::fs;
use std::fs::OpenOptions;
use serde::{Deserialize, Serialize};
use phase2::parameters::MPCParameters;
use phase2::circom_circuit::CircomCircuit;
use phase2::utils::repr_to_big;
use bellman_ce::groth16::{prepare_verifying_key, create_random_proof, verify_proof};
use bellman_ce::pairing::{
    Engine,
    CurveAffine,
    ff::{
        PrimeField,
    },
    bn256::{
        Bn256,
    },
};

#[derive(Serialize, Deserialize)]
struct ProofJson {
    pub protocol: String,
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
}


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

    let should_filter_points_at_infinity = false;
    let rng = &mut rand::XorShiftRng::new_unseeded(); // TODO: change this unsafe unseeded random (!)

    let mut c = CircomCircuit::from_json_file(circuit_filename);
    c.load_witness_json_file(witness_filename);
    let input = c.inputs.to_vec();

    let reader = OpenOptions::new()
        .read(true)
        .open(params_filename)
        .expect("unable to open.");

    let mut params = MPCParameters::read(reader, should_filter_points_at_infinity, true).expect("unable to read params");

    params.filter_params();
    let params = params.get_params();

    println!("Proving...");
    let proof = create_random_proof(c, &*params, rng).unwrap();

    println!("Checking proof");
    let pvk = prepare_verifying_key(&params.vk);
    let result = verify_proof(
        &pvk,
        &proof,
        &input[1..]
    ).unwrap();
    assert!(result, "Proof is correct");

    let p1_to_vec = |p : &<Bn256 as Engine>::G1Affine| {
        vec![
            repr_to_big(p.get_x().into_repr()),
            repr_to_big(p.get_y().into_repr()),
            if p.is_zero() { "0".to_string() } else { "1".to_string() }
        ]
    };
    let p2_to_vec = |p : &<Bn256 as Engine>::G2Affine| {
        vec![
            vec![
                repr_to_big(p.get_x().c0.into_repr()),
                repr_to_big(p.get_x().c1.into_repr()),
            ],
            vec![
                repr_to_big(p.get_y().c0.into_repr()),
                repr_to_big(p.get_y().c1.into_repr()),
            ],
            if p.is_zero() {
                vec!["0".to_string(), "0".to_string()]
            } else {
                vec!["1".to_string(), "0".to_string()]
            }
        ]
    };

    let proof = ProofJson {
        protocol: "groth".to_string(),
        pi_a: p1_to_vec(&proof.a),
        pi_b: p2_to_vec(&proof.b),
        pi_c: p1_to_vec(&proof.c),
    };

    let proof_json = serde_json::to_string(&proof).unwrap();
    fs::write(proof_filename, proof_json.as_bytes()).unwrap();

    let mut public_inputs = vec![];
    for x in input[1..].iter() {
        public_inputs.push(repr_to_big(x.into_repr()));
    }
    let public_json = serde_json::to_string(&public_inputs).unwrap();
    fs::write(public_filename, public_json.as_bytes()).unwrap();

    println!("Done!")
}
