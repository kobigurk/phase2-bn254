extern crate bellman_ce;
extern crate rand;
extern crate phase2;
extern crate exitcode;
extern crate serde;
extern crate serde_json;
extern crate num_bigint;
extern crate num_traits;
extern crate itertools;

use std::fs;
use std::fs::OpenOptions;
use std::iter::repeat;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use phase2::parameters::MPCParameters;
use phase2::utils::{
    p1_to_vec,
    p2_to_vec,
    pairing_to_vec,
};
use bellman_ce::pairing::{
    Engine,
    bn256::{
        Bn256,
    }
};

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
    // Todo: add json fields: nPublic, nVars, polsA, polsB, polsC, protocol: groth
}

#[derive(Serialize, Deserialize)]
struct VerifyingKeyJson {
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
    pub vk_alfa_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    pub vk_alfabeta_12: Vec<Vec<Vec<String>>>,
    pub protocol: String,
    #[serde(rename = "nPublic")]
    pub inputs_count: usize,
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

    let disallow_points_at_infinity = false;

    println!("Exporting {}...", params_filename);

    let reader = OpenOptions::new()
                            .read(true)
                            .open(params_filename)
                            .expect("unable to open.");
    let params = MPCParameters::read(reader, disallow_points_at_infinity, true).expect("unable to read params");
    let params = params.get_params();

    let proving_key = ProvingKeyJson {
        a: params.a.iter().map(|e| p1_to_vec(e)).collect_vec(),
        b1: params.b_g1.iter().map(|e| p1_to_vec(e)).collect_vec(),
        b2: params.b_g2.iter().map(|e| p2_to_vec(e)).collect_vec(),
        c: repeat(None).take(params.vk.ic.len()).chain(params.l.iter().map(|e| Some(p1_to_vec(e)))).collect_vec(),
        vk_alfa_1: p1_to_vec(&params.vk.alpha_g1),
        vk_beta_1: p1_to_vec(&params.vk.beta_g1),
        vk_delta_1: p1_to_vec(&params.vk.delta_g1),
        vk_beta_2: p2_to_vec(&params.vk.beta_g2),
        vk_delta_2: p2_to_vec(&params.vk.delta_g2),
        h: params.h.iter().map(|e| p1_to_vec(e)).collect_vec(),
    };

    let verification_key = VerifyingKeyJson {
        ic: params.vk.ic.iter().map(|e| p1_to_vec(e)).collect_vec(),
        vk_alfa_1: p1_to_vec(&params.vk.alpha_g1),
        vk_beta_2: p2_to_vec(&params.vk.beta_g2),
        vk_gamma_2: p2_to_vec(&params.vk.gamma_g2),
        vk_delta_2: p2_to_vec(&params.vk.delta_g2),
        vk_alfabeta_12: pairing_to_vec(&Bn256::pairing(params.vk.alpha_g1, params.vk.beta_g2)),
        inputs_count: params.vk.ic.len() - 1,
        protocol: String::from("groth"),
    };

    let pk_json = serde_json::to_string(&proving_key).unwrap();
    let vk_json = serde_json::to_string(&verification_key).unwrap();
    fs::write(pk_filename, pk_json.as_bytes()).unwrap();
    fs::write(vk_filename, vk_json.as_bytes()).unwrap();

    println!("Created {} and {}.", pk_filename, vk_filename);
}
