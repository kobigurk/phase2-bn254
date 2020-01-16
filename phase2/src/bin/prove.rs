#![allow(unused_imports)]

extern crate phase2;
extern crate bellman_ce;

use phase2::circom_circuit::CircomCircuit;
use std::fs::OpenOptions;
use phase2::parameters::MPCParameters;
use bellman_ce::groth16::{Proof, generate_random_parameters, prepare_verifying_key, create_random_proof, verify_proof};
use std::sync::Arc;

use bellman_ce::pairing::bn256::{
    Bn256,
};

use bellman_ce::pairing::{
    Engine,
    CurveAffine,
    ff::{
        Field,
        PrimeField,
    },
};

use bellman_ce::{
    Circuit,
    SynthesisError,
    Variable,
    Index,
    ConstraintSystem,
    LinearCombination,
};

fn main() {
    let should_filter_points_at_infinity = false;
    let rng = &mut rand::XorShiftRng::new_unseeded(); // TODO: change this unsafe unseeded random (!)

    let mut c = CircomCircuit::from_json("circuit.json");
    c.load_witness_json("witness.json");
    let input = c.inputs.to_vec();

    let reader = OpenOptions::new()
        .read(true)
        .open("circom4.params")
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
    println!("Done!")
}