#![allow(unused_imports)]

extern crate phase2;
extern crate bellman_ce;
extern crate num_bigint;
extern crate num_traits;
extern crate exitcode;
extern crate serde;

use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use num_bigint::BigUint;
use num_traits::Num;
use phase2::utils::repr_to_big;
use phase2::parameters::MPCParameters;
use bellman_ce::pairing::{
    Engine,
    CurveAffine,
    ff::PrimeField,
    bn256::{
        Bn256,
    }
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("Usage: \n<params> <out_contract.sol>");
        std::process::exit(exitcode::USAGE);
    }
    let params_filename = &args[1];
    let verifier_filename = &args[2];

    let should_filter_points_at_infinity = false;
    let bytes = include_bytes!("../verifier_groth.sol");
    let template = String::from_utf8_lossy(bytes);

    let reader = OpenOptions::new()
        .read(true)
        .open(params_filename)
        .expect("unable to open.");

    let params = MPCParameters::read(reader, should_filter_points_at_infinity, true).expect("unable to read params");
    let vk = &params.get_params().vk;

    let p1_to_str = |p: &<Bn256 as Engine>::G1Affine| {
        let x = repr_to_big(p.get_x().into_repr());
        let y = repr_to_big(p.get_y().into_repr());
        return format!("{}, {}", x, y)
    };
    let p2_to_str = |p: &<Bn256 as Engine>::G2Affine| {
        let x = p.get_x();
        let y = p.get_y();
        let x_c0 = repr_to_big(x.c0.into_repr());
        let x_c1 = repr_to_big(x.c1.into_repr());
        let y_c0 = repr_to_big(y.c0.into_repr());
        let y_c1 = repr_to_big(y.c1.into_repr());
        format!("[{}, {}], [{}, {}]", x_c0, x_c1, y_c0, y_c1)
    };

    let template = template.replace("<%vk_alfa1%>", &*p1_to_str(&vk.alpha_g1));
    let template = template.replace("<%vk_beta2%>", &*p2_to_str(&vk.beta_g2));
    let template = template.replace("<%vk_gamma2%>", &*p2_to_str(&vk.gamma_g2));
    let template = template.replace("<%vk_delta2%>", &*p2_to_str(&vk.delta_g2));

    let template = template.replace("<%vk_ic_length%>", &*vk.ic.len().to_string());
    let template = template.replace("<%vk_input_length%>", &*(vk.ic.len() - 1).to_string());

    let mut vi = String::from("");
    for i in 0..vk.ic.len() {
        vi = format!("{}{}vk.IC[{}] = Pairing.G1Point({});\n", vi, if vi.len() == 0 { "" } else { "        " }, i, &*p1_to_str(&vk.ic[i]));
    }
    let template = template.replace("<%vk_ic_pts%>", &*vi);

    fs::write(verifier_filename, template.as_bytes()).unwrap();
    println!("Created {}", verifier_filename);
}