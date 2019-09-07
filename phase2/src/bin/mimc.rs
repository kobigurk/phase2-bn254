extern crate bellman_ce;
extern crate rand;
extern crate phase2;
extern crate num_bigint;
extern crate num_traits;

#[macro_use]
extern crate serde;
extern crate serde_json;

use num_bigint::BigUint;
use num_traits::Num;
use std::ops::DerefMut;
use std::io::Write;

use std::sync::Arc;
use serde::{Deserialize, Serialize};
// For randomness (during paramgen and proof generation)
use rand::{thread_rng, Rng};

// For benchmarking
use std::time::{Duration, Instant};

// Bring in some tools for using pairing-friendly curves
use bellman_ce::pairing::{
    Engine,
    CurveAffine,
    ff::{Field, PrimeField},
};

// We're going to use the BLS12-381 pairing-friendly elliptic curve.
use bellman_ce::pairing::bn256::{
    Bn256
};

// We'll use these interfaces to construct our circuit.
use bellman_ce::{
    Circuit,
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

use std::fs::File;
use std::fs::{OpenOptions, remove_file};

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

const MIMC_ROUNDS: usize = 322;

/// This is an implementation of MiMC, specifically a
/// variant named `LongsightF322p3` for BLS12-381.
/// See http://eprint.iacr.org/2016/492 for more 
/// information about this construction.
///
/// ```
/// function LongsightF322p3(xL ⦂ Fp, xR ⦂ Fp) {
///     for i from 0 up to 321 {
///         xL, xR := xR + (xL + Ci)^3, xL
///     }
///     return xL
/// }
/// ```
fn mimc<E: Engine>(
    mut xl: E::Fr,
    mut xr: E::Fr,
    constants: &[E::Fr]
) -> E::Fr
{
    assert_eq!(constants.len(), MIMC_ROUNDS);

    for i in 0..MIMC_ROUNDS {
        let mut tmp1 = xl;
        tmp1.add_assign(&constants[i]);
        let mut tmp2 = tmp1;
        tmp2.square();
        tmp2.mul_assign(&tmp1);
        tmp2.add_assign(&xr);
        xr = xl;
        xl = tmp2;
    }

    xl
}

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
struct MiMCDemo<'a, E: Engine> {
    xl: Option<E::Fr>,
    xr: Option<E::Fr>,
    constants: &'a [E::Fr]
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for MiMCDemo<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Allocate the first component of the preimage.
        let mut xl_value = self.xl;
        let mut xl = cs.alloc(|| "preimage xl", || {
            xl_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate the second component of the preimage.
        let mut xr_value = self.xr;
        let mut xr = cs.alloc(|| "preimage xr", || {
            xr_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        for i in 0..MIMC_ROUNDS {
            // xL, xR := xR + (xL + Ci)^3, xL
            let cs = &mut cs.namespace(|| format!("round {}", i));

            // tmp = (xL + Ci)^2
            let mut tmp_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.square();
                e
            });
            let mut tmp = cs.alloc(|| "tmp", || {
                tmp_value.ok_or(SynthesisError::AssignmentMissing)
            })?;

            cs.enforce(
                || "tmp = (xL + Ci)^2",
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + tmp
            );

            // new_xL = xR + (xL + Ci)^3
            // new_xL = xR + tmp * (xL + Ci)
            // new_xL - xR = tmp * (xL + Ci)
            let mut new_xl_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.mul_assign(&tmp_value.unwrap());
                e.add_assign(&xr_value.unwrap());
                e
            });

            let mut new_xl = if i == (MIMC_ROUNDS-1) {
                // This is the last round, xL is our image and so
                // we allocate a public input.
                cs.alloc_input(|| "image", || {
                    new_xl_value.ok_or(SynthesisError::AssignmentMissing)
                })?
            } else {
                cs.alloc(|| "new_xl", || {
                    new_xl_value.ok_or(SynthesisError::AssignmentMissing)
                })?
            };

            cs.enforce(
                || "new_xL = xR + (xL + Ci)^3",
                |lc| lc + tmp,
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + new_xl - xr
            );

            // xR = xL
            xr = xl;
            xr_value = xl_value;

            // xL = new_xL
            xl = new_xl;
            xl_value = new_xl_value;
        }

        Ok(())
    }
}

fn main() {
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut thread_rng();

    // Generate the MiMC round constants
    let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();

    println!("Creating parameters...");

    let should_filter_points_at_infinity = false;

    // Create parameters for our circuit
    let mut params = {
        let c = MiMCDemo::<Bn256> {
            xl: None,
            xr: None,
            constants: &constants
        };

        phase2::MPCParameters::new(c, should_filter_points_at_infinity).unwrap()
    };

    let old_params = params.clone();
    params.contribute(rng);

    let first_contrib = phase2::verify_contribution(&old_params, &params).expect("should verify");

    let old_params = params.clone();
    params.contribute(rng);

    let second_contrib = phase2::verify_contribution(&old_params, &params).expect("should verify");

    let verification_result = params.verify(MiMCDemo::<Bn256> {
        xl: None,
        xr: None,
        constants: &constants
    }, should_filter_points_at_infinity).unwrap();

    assert!(phase2::contains_contribution(&verification_result, &first_contrib));
    assert!(phase2::contains_contribution(&verification_result, &second_contrib));

    let params = params.get_params();

    let mut f = File::create("mimc.params").unwrap();
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
    const SAMPLES: u32 = 50;
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    // Just a place to put the proof data, so we can
    // benchmark deserialization.
    let mut proof_vec = vec![];

    for _ in 0..SAMPLES {
        // Generate a random preimage and compute the image
        let xl = rng.gen();
        let xr = rng.gen();
        let image = mimc::<Bn256>(xl, xr, &constants);

        proof_vec.truncate(0);

        let start = Instant::now();
        {
            // Create an instance of our circuit (with the
            // witness)
            let c = MiMCDemo {
                xl: Some(xl),
                xr: Some(xr),
                constants: &constants
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
            &[image]
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
