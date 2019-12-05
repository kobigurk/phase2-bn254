extern crate bellman_ce;
extern crate rand;
extern crate phase2;
extern crate memmap;
extern crate num_bigint;
extern crate num_traits;
extern crate exitcode;

extern crate serde;
extern crate serde_json;

use serde::{Deserialize, Serialize};
use num_bigint::BigUint;
use num_traits::Num;

use std::fs::OpenOptions;
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
    ff::PrimeField,
};

// We're going to use the BLS12-381 pairing-friendly elliptic curve.
use bellman_ce::pairing::bn256::{
    Bn256,
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        println!("Usage: \n<in_params.params> <out_vk.json> <out_pk.json>");
        std::process::exit(exitcode::USAGE);
    }
    let params_filename = &args[1];
    let vk_filename = &args[2];
    let pk_filename = &args[3];

    println!("Exporting {}...", params_filename);

    let reader = OpenOptions::new()
                            .read(true)
                            .open(params_filename)
                            .expect("unable to open.");
    let params = phase2::MPCParameters::read(reader, true).expect("unable to read params");
    let params = params.get_params();

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
        //println!("test: {}", p.get_x().into_repr());
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

    let pk_file = OpenOptions::new().read(true).write(true).create_new(true).open(pk_filename).unwrap();
    let pk_json = serde_json::to_string(&proving_key).unwrap();
    pk_file.set_len(pk_json.len() as u64).expect("unable to write pk file");
    let mut mmap = unsafe { memmap::Mmap::map(&pk_file) }.unwrap().make_mut().unwrap();
    mmap.deref_mut().write_all(pk_json.as_bytes()).unwrap();

    let vk_file = OpenOptions::new().read(true).write(true).create_new(true).open(vk_filename).unwrap();
    let vk_json = serde_json::to_string(&verification_key).unwrap();
    vk_file.set_len(vk_json.len() as u64).expect("unable to write vk file");
    let mut mmap = unsafe { memmap::Mmap::map(&vk_file) }.unwrap().make_mut().unwrap();
    mmap.deref_mut().write_all(vk_json.as_bytes()).unwrap();

    println!("Created {} and {}.", pk_filename, vk_filename);
}
