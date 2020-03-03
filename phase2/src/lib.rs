use cfg_if::cfg_if;

mod keypair;

pub mod parameters;
mod polynomial;

cfg_if! {
    if #[cfg(feature = "wasm")] {
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

            log!("Initializing phase2");
            let mut rng = &mut rand::XorShiftRng::new_unseeded(); // TODO: change this unsafe unseeded random (!)
            let mut params = MPCParameters::read(&*params, true).expect("unable to read params");

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
