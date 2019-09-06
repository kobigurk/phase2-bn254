extern crate bellman_ce;
extern crate rand;
extern crate phase2;
extern crate memmap;

#[macro_use]
extern crate serde;
extern crate serde_json;

use serde::{Deserialize, Serialize};
use std::str;

// For randomness (during paramgen and proof generation)
use rand::{thread_rng, Rng};

// For benchmarking
use std::time::{Duration, Instant};

use std::fs::File;
use std::io;

// Bring in some tools for using pairing-friendly curves
use bellman_ce::pairing::{
    Engine,
    ff::{Field, PrimeField},
};

// We're going to use the BLS12-381 pairing-friendly elliptic curve.
use bellman_ce::pairing::bn256::{
    Bn256,
};

// We'll use these interfaces to construct our circuit.
use bellman_ce::{
    Circuit,
    Variable,
    Index,
    LinearCombination,
    ConstraintSystem,
    SynthesisError
};

// We're going to use the Groth16 proving system.
use bellman_ce::groth16::{
    Proof,
    prepare_verifying_key,
    create_random_proof,
    verify_proof,
};

use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
struct CircuitJson {
    pub constraints: Vec<Vec<HashMap<String, String>>>,
    #[serde(rename = "nInputs")]
    pub num_inputs: usize,
    #[serde(rename = "nOutputs")]
    pub num_outputs: usize,
    #[serde(rename = "nVars")]
    pub num_variables: usize,
}

struct CircomCircuit<'a> {
    pub file_name: &'a str,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for CircomCircuit<'a> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let mmap = unsafe { memmap::Mmap::map(&File::open(self.file_name)?) }?;
        let content = str::from_utf8(&mmap).unwrap();
        let circuit_json: CircuitJson = serde_json::from_str(&content).unwrap();
        let return_err = || Err(SynthesisError::AssignmentMissing);
        let num_public_inputs = circuit_json.num_inputs + circuit_json.num_outputs;
        for i in 0..circuit_json.num_variables {
            if i < num_public_inputs {
                cs.alloc_input(|| format!("variable {}", i), return_err);
            } else {
                cs.alloc(|| format!("variable {}", i), return_err);
            }
        }
        let mut constraint_num = 0;
        for constraint in circuit_json.constraints.iter() {
            let mut lcs = vec![];
            for lc_description in constraint {
                let mut lc = LinearCombination::<E>::zero();
                for (var_index_str, coefficient_str) in lc_description {
                    let var_index_num: usize = var_index_str.parse().unwrap();
                    let var_index = if var_index_num < num_public_inputs {
                        Index::Input(var_index_num)
                    } else {
                        Index::Aux(var_index_num - num_public_inputs)
                    };
                    lc = lc + (E::Fr::from_str(coefficient_str).unwrap(), Variable::new_unchecked(var_index));
                }
                lcs.push(lc);
            }
            cs.enforce(|| format!("constraint {}", constraint_num), |_| lcs[0].clone(), |_| lcs[1].clone(), |_| lcs[2].clone());
            constraint_num += 1;
        }
        Ok(())
    }
}

fn main() {
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut thread_rng();


    println!("Creating parameters...");

    let file_name = "circuit.json";
    // Create parameters for our circuit
    let mut params = {
        let c = CircomCircuit {
            file_name,
        };

        phase2::MPCParameters::new(c).unwrap()
    };

    let old_params = params.clone();
    params.contribute(rng);

    let first_contrib = phase2::verify_contribution(&old_params, &params).expect("should verify");

    let old_params = params.clone();
    params.contribute(rng);

    let second_contrib = phase2::verify_contribution(&old_params, &params).expect("should verify");

    let verification_result = params.verify(CircomCircuit {
        file_name,
    }).unwrap();

    assert!(phase2::contains_contribution(&verification_result, &first_contrib));
    assert!(phase2::contains_contribution(&verification_result, &second_contrib));

    let params = params.get_params();

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    // Let's benchmark stuff!
    const SAMPLES: u32 = 50;
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    // Just a place to put the proof data, so we can
    // benchmark deserialization.
    let mut proof_vec = vec![];

    for _ in 0..SAMPLES {
        proof_vec.truncate(0);

        let start = Instant::now();
        {
            // Create an instance of our circuit (with the
            // witness)
            let c = CircomCircuit {
                file_name,
            };

            // Create a groth16 proof with our parameters.
            let proof = create_random_proof(c, params, rng).unwrap();

            proof.write(&mut proof_vec).unwrap();
        }

        total_proving += start.elapsed();

        let start = Instant::now();
        let proof = Proof::read(&proof_vec[..]).unwrap();
        // Check the proof
        assert!(verify_proof(
            &pvk,
            &proof,
            &[]
        ).unwrap());
        total_verifying += start.elapsed();
    }
    let proving_avg = total_proving / SAMPLES;
    let proving_avg = proving_avg.subsec_nanos() as f64 / 1_000_000_000f64
                      + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / SAMPLES;
    let verifying_avg = verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64
                      + (verifying_avg.as_secs() as f64);

    println!("Average proving time: {:?} seconds", proving_avg);
    println!("Average verifying time: {:?} seconds", verifying_avg);
}
