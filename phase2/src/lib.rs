#![allow(unused_imports)]

#[macro_use]
extern crate serde;
extern crate bellman_ce;
extern crate rand;
extern crate byteorder;
extern crate blake2_rfc;
extern crate num_cpus;
extern crate crossbeam;
extern crate num_bigint;
extern crate num_traits;
extern crate cfg_if;
extern crate itertools;

use cfg_if::cfg_if;

pub mod keypair;
pub mod keypair_assembly;
pub mod hash_writer;
pub mod parameters;
pub mod utils;
pub mod circom_circuit;

cfg_if! {
    if #[cfg(feature = "wasm")] {
        extern crate serde_json;
        extern crate js_sys;
        extern crate web_sys;
        extern crate wasm_bindgen;
        extern crate console_error_panic_hook;
        extern crate itertools;

        use wasm_bindgen::prelude::*;
        use itertools::Itertools;
        use parameters::MPCParameters;
        use std::io::{
            Read,
            Write,
        };

        macro_rules! log {
            ($($t:tt)*) => (web_sys::console::log_1(&format_args!($($t)*).to_string().into()))
        }

        #[wasm_bindgen]
        pub fn contribute(params: Vec<u8>) -> Result<Vec<u8>, JsValue> {
            console_error_panic_hook::set_once();
            let disallow_points_at_infinity = false;

            log!("Initializing phase2");
            let mut rng = &mut rand::XorShiftRng::new_unseeded(); // TODO: change this unsafe unseeded random (!)
            let mut params = MPCParameters::read(&*params, disallow_points_at_infinity, true).expect("unable to read params");

            log!("Contributing...");
            let hash = params.contribute(&mut rng);
            log!("Contribution hash: 0x{:02x}", hash.iter().format(""));

            let mut output: Vec<u8> = vec![];
            params.write(&mut output).expect("failed to write updated parameters");
            log!("Returning parameters");
            Ok(output)
        }
    }
}
