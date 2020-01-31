extern crate phase2;
extern crate exitcode;

use phase2::circom_circuit::{
    proving_key_json_file,
    verification_key_json_file,
    load_params_file
};

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
    let params = load_params_file(params_filename);
    proving_key_json_file(&params, pk_filename).unwrap();
    verification_key_json_file(&params, vk_filename).unwrap();
    println!("Created {} and {}.", pk_filename, vk_filename);
}
