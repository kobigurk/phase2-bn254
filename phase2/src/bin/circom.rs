extern crate bellman_ce;
extern crate rand;
extern crate phase2;
extern crate memmap;
extern crate num_bigint;
extern crate num_traits;

#[macro_use]
extern crate serde;
extern crate serde_json;

use serde::{Deserialize, Serialize};
use num_bigint::BigUint;
use num_traits::Num;

// For randomness (during paramgen and proof generation)
use rand::{thread_rng, ChaChaRng, Rng};

// For benchmarking
use std::time::{Duration, Instant};
use std::str;

use std::fs::File;
use std::fs::{OpenOptions, remove_file};
use std::io::Write;
use std::ops::DerefMut;

#[derive(Serialize, Deserialize)]
struct ProvingKeyJson {
    #[serde(rename = "A")]
    pub a: Vec<Vec<String>>,
    #[serde(rename = "B1")]
    pub b1: Vec<Vec<String>>,
    #[serde(rename = "B2")]
    pub b2: Vec<Vec<Vec<String>>>,
    #[serde(rename = "C")]
    pub c: Vec<Option<Vec<String>>>,
    pub vk_alfa_1: Vec<String>,
    pub vk_beta_1: Vec<String>,
    pub vk_delta_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "hExps")]
    pub h: Vec<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct VerifyingKeyJson {
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
    pub vk_alfa_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
}

// Bring in some tools for using pairing-friendly curves
use bellman_ce::pairing::{
    Engine,
    CurveAffine,
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

use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
struct CircuitJson {
    pub constraints: Vec<Vec<BTreeMap<String, String>>>,
    #[serde(rename = "nPubInputs")]
    pub num_inputs: usize,
    #[serde(rename = "nOutputs")]
    pub num_outputs: usize,
    #[serde(rename = "nVars")]
    pub num_variables: usize,
}

struct CircomCircuit<'a> {
    pub file_name: &'a str,
    pub witness: Vec<String>,
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
        let num_public_inputs = circuit_json.num_inputs + circuit_json.num_outputs + 1;
        println!("num public inputs: {}", num_public_inputs);
        for i in 1..circuit_json.num_variables {
            if i < num_public_inputs {
                //println!("allocating public input {}", i);
                cs.alloc_input(|| format!("variable {}", i), || {
                    println!("variable {}: {}", i, &self.witness[i]);
                    Ok(E::Fr::from_str(&self.witness[i]).unwrap())
                });
            } else {
                //println!("allocating private input {}", i);
                cs.alloc(|| format!("variable {}", i), || {
                    println!("variable {}: {}", i, &self.witness[i]);
                    Ok(E::Fr::from_str(&self.witness[i]).unwrap())
                });
            }
        }
        let mut constrained: BTreeMap<usize, bool> = BTreeMap::new();
        let mut constraint_num = 0;
        for (i, constraint) in circuit_json.constraints.iter().enumerate() {
            let mut lcs = vec![];
            for lc_description in constraint {
                let mut lc = LinearCombination::<E>::zero();
                //println!("lc_description: {:?}, i: {}, len: {}", lc_description, i, constraint.len());
                for (var_index_str, coefficient_str) in lc_description {
                    //println!("var_index_str: {}, coefficient_str: {}", var_index_str, coefficient_str);
                    let var_index_num: usize = var_index_str.parse().unwrap();
                    let var_index = if var_index_num < num_public_inputs {
                        Index::Input(var_index_num)
                    } else {
                        Index::Aux(var_index_num - num_public_inputs)
                    };
                    constrained.insert(var_index_num, true);
                    if i == 2 {
                        lc = lc + (E::Fr::from_str(coefficient_str).unwrap(), Variable::new_unchecked(var_index));
                    } else {
                        lc = lc + (E::Fr::from_str(coefficient_str).unwrap(), Variable::new_unchecked(var_index));
                    }
                }
                lcs.push(lc);
            }
            cs.enforce(|| format!("constraint {}", constraint_num), |_| lcs[0].clone(), |_| lcs[1].clone(), |_| lcs[2].clone());
            constraint_num += 1;
        }
        println!("contraints: {}", circuit_json.constraints.len());
        let mut unconstrained: BTreeMap<usize, bool> = BTreeMap::new();
        for i in 0..circuit_json.num_variables { 
            if !constrained.contains_key(&i) {
                unconstrained.insert(i, true);
            }
        }
        for (i, _) in unconstrained {
            println!("variable {} is unconstrained", i);
        }
        Ok(())
    }
}

fn main() {
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    //let rng = &mut thread_rng();
    let mut rng = ChaChaRng::new_unseeded();
    rng.set_counter(0u64, 1234567890u64);
    let rng = &mut rng;


    println!("Creating parameters...");

    let should_filter_points_at_infinity = false;

    let file_name = "circuit.json";

    let mmap = unsafe { memmap::Mmap::map(&File::open("witness.json").unwrap()) }.unwrap();
    let content = str::from_utf8(&mmap).unwrap();

    let witness: Vec<String> = serde_json::from_str(&content).unwrap();
    // Create parameters for our circuit
    let mut params = {
        let c = CircomCircuit {
            file_name,
            witness: witness.clone(),
        };

        phase2::MPCParameters::new(c, should_filter_points_at_infinity).unwrap()
    };

    let old_params = params.clone();
    params.contribute(rng);

    let first_contrib = phase2::verify_contribution(&old_params, &params).expect("should verify");

    let old_params = params.clone();
    params.contribute(rng);

    let second_contrib = phase2::verify_contribution(&old_params, &params).expect("should verify");

    let verification_result = params.verify(CircomCircuit {
        file_name,
        witness: witness.clone(),
    }, should_filter_points_at_infinity).unwrap();

    assert!(phase2::contains_contribution(&verification_result, &first_contrib));
    assert!(phase2::contains_contribution(&verification_result, &second_contrib));

    let params = params.get_params();

    let mut f = File::create("circom.params").unwrap();
    params.write(&mut f);

    let mut proving_key = ProvingKeyJson {
        a: vec![],
        b1: vec![],
        b2: vec![],
        c: vec![],
        vk_alfa_1: vec![],
        vk_beta_1: vec![],
        vk_delta_1: vec![],
        vk_beta_2: vec![],
        vk_delta_2: vec![],
        h: vec![],
    };
    let repr_to_big = |r| {
        BigUint::from_str_radix(&format!("{}", r)[2..], 16).unwrap().to_str_radix(10)
    };

    let p1_to_vec = |p : &<Bn256 as Engine>::G1Affine| {
        let mut v = vec![];
        let x = repr_to_big(p.get_x().into_repr());
        v.push(x);
        let y = repr_to_big(p.get_y().into_repr());
        v.push(y);
        if p.is_zero() { 
            v.push("0".to_string());
        } else {
            v.push("1".to_string());
        }
        v
    };
    let p2_to_vec = |p : &<Bn256 as Engine>::G2Affine| {
        let mut v = vec![];
        let x = p.get_x();
        let mut x_v = vec![];
        x_v.push(repr_to_big(x.c0.into_repr()));
        x_v.push(repr_to_big(x.c1.into_repr()));
        v.push(x_v);

        let y = p.get_y();
        let mut y_v = vec![];
        y_v.push(repr_to_big(y.c0.into_repr()));
        y_v.push(repr_to_big(y.c1.into_repr()));
        v.push(y_v);

        if p.is_zero() { 
            v.push(["0".to_string(), "0".to_string()].to_vec());
        } else {
            v.push(["1".to_string(), "0".to_string()].to_vec());
        }

        v
    };
    let a = params.a.clone();
    for e in a.iter() {
        proving_key.a.push(p1_to_vec(e));
    }
    let b1 = params.b_g1.clone();
    for e in b1.iter() {
        proving_key.b1.push(p1_to_vec(e));
    }
    let b2 = params.b_g2.clone();
    for e in b2.iter() {
        proving_key.b2.push(p2_to_vec(e));
    }
    let c = params.l.clone();
    for _ in 0..params.vk.ic.len() {
        proving_key.c.push(None);
    }
    for e in c.iter() {
        proving_key.c.push(Some(p1_to_vec(e)));
    }

    let vk_alfa_1 = params.vk.alpha_g1.clone();
    proving_key.vk_alfa_1 = p1_to_vec(&vk_alfa_1);

    let vk_beta_1 = params.vk.beta_g1.clone();
    proving_key.vk_beta_1 = p1_to_vec(&vk_beta_1);

    let vk_delta_1 = params.vk.delta_g1.clone();
    proving_key.vk_delta_1 = p1_to_vec(&vk_delta_1);

    let vk_beta_2 = params.vk.beta_g2.clone();
    proving_key.vk_beta_2 = p2_to_vec(&vk_beta_2);

    let vk_delta_2 = params.vk.delta_g2.clone();
    proving_key.vk_delta_2 = p2_to_vec(&vk_delta_2);

    let h = params.h.clone();
    for e in h.iter() {
        proving_key.h.push(p1_to_vec(e));
    }


    let mut verification_key = VerifyingKeyJson {
        ic: vec![],
        vk_alfa_1: vec![],
        vk_beta_2: vec![],
        vk_gamma_2: vec![],
        vk_delta_2: vec![],
    };

    let ic = params.vk.ic.clone();
    for e in ic.iter() {
        verification_key.ic.push(p1_to_vec(e));
    }

    verification_key.vk_alfa_1 = p1_to_vec(&vk_alfa_1);
    verification_key.vk_beta_2 = p2_to_vec(&vk_beta_2);
    //let vk_alfabeta_12 = vk_alfa_1.pairing_with(&vk_beta_2);
    //println!("vk_alfabeta_12: {}", vk_alfabeta_12);
    let vk_gamma_2 = params.vk.gamma_g2.clone();
    verification_key.vk_gamma_2 = p2_to_vec(&vk_gamma_2);
    verification_key.vk_delta_2 = p2_to_vec(&vk_delta_2);

    let mut pk_file = OpenOptions::new().read(true).write(true).create_new(true).open("pk.json").unwrap();
    let pk_json = serde_json::to_string(&proving_key).unwrap();
    pk_file.set_len(pk_json.len() as u64);
    let mut mmap = unsafe { memmap::Mmap::map(&pk_file) }.unwrap().make_mut().unwrap();
    mmap.deref_mut().write_all(pk_json.as_bytes()).unwrap();

    let mut vk_file = OpenOptions::new().read(true).write(true).create_new(true).open("vk.json").unwrap();
    let vk_json = serde_json::to_string(&verification_key).unwrap();
    vk_file.set_len(vk_json.len() as u64);
    let mut mmap = unsafe { memmap::Mmap::map(&vk_file) }.unwrap().make_mut().unwrap();
    mmap.deref_mut().write_all(vk_json.as_bytes()).unwrap();

    /*
    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    // Let's benchmark stuff!
    const SAMPLES: u32 = 1;
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
                witness: witness.clone(),
            };

            // Create a groth16 proof with our parameters.
            let proof = create_random_proof(c, params, rng).unwrap();
            println!("proof: {:?}", proof);

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
    */
}
