use serde_json::*;
use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        println!("Usage: \n<reference_key.json> <in_key.json> <out_key.json>");
        std::process::exit(exitcode::USAGE);
    }
    let ref_file = &args[1];
    let in_file = &args[2];
    let out_file = &args[3];

    let in_json: Map<String, Value> =
        serde_json::from_str(&fs::read_to_string(in_file).unwrap()).unwrap();
    let mut reference_json: Map<String, Value> =
        serde_json::from_str(&fs::read_to_string(ref_file).unwrap()).unwrap();

    for (key, value) in &in_json {
        reference_json[key] = value.clone();
    }

    fs::write(
        out_file,
        serde_json::to_string(&reference_json).unwrap().as_bytes(),
    )
    .unwrap();
    println!("Done");
}
