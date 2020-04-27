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
extern crate blake2;

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
        pub fn contribute(params: Vec<u8>, entropy: Vec<u8>) -> Result<Vec<u8>, JsValue> {
            console_error_panic_hook::set_once();
            let disallow_points_at_infinity = false;

            log!("Initializing phase2");
            // Create an RNG based on provided randomness
            let mut rng = {
                use byteorder::{BigEndian, ReadBytesExt};
                use blake2::{Blake2b, Digest};
                use rand::{SeedableRng};
                use rand::chacha::ChaChaRng;
                
                let h = {
                    let mut h = Blake2b::default();
                    h.input(&*entropy);
                    h.result()
                };
                let mut digest = &h[..];
                
                // Interpret the first 32 bytes of the digest as 8 32-bit words
                let mut seed = [0u32; 8];
                for i in 0..8 {
                    seed[i] = digest.read_u32::<BigEndian>().expect("digest is large enough for this to work");
                }
                
                ChaChaRng::from_seed(&seed)
            };
        
            let mut params = MPCParameters::read(&*params, disallow_points_at_infinity, true).expect("unable to read params");

            log!("Contributing...");
            let hash = params.contribute(&mut rng);
            log!("Contribution hash: 0x{:02x}", hash.iter().format(""));

            let mut output: Vec<u8> = vec![];
            params.write(&mut output).expect("failed to write updated parameters");
            log!("Returning parameters");

            Ok(hash
                .iter().cloned()
                .chain(output.iter().cloned())
                .collect()
            )
        }
    }
}
